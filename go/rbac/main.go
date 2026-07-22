// Command trustlens-rbac answers Kubernetes RBAC authorization questions offline, using
// the upstream authorizer rather than an approximation of it.
//
// Why this exists as a separate binary rather than Python code: hand-rolling RBAC
// evaluation would repeat the mistake GROUNDING.md forbids for IAM. Aggregation, wildcard
// precedence, nonResourceURLs, subresource matching and the cluster-versus-namespace
// binding rules are exactly the details an approximation gets subtly wrong. The upstream
// implementation is authoritative, so it is reused.
//
// It is OPTIONAL. Its absence makes the capabilities it would have covered UNSUPPORTED in
// the TrustLens record, with the reason stated — never a clean result. It is also fully
// out of the core scan path: nothing in `trustlens scan` or `trustlens map-credentials`
// can reach it.
//
// Inertness: this reads files and writes JSON to stdout. It opens no socket, contacts no
// cluster, and uses no kubeconfig. Manifests are decoded with sigs.k8s.io/yaml, which
// routes through encoding/json and cannot construct arbitrary objects.
//
// Output is deterministic: every collection is sorted before emission. The two RBAC graph
// tools TrustLens rejected are non-deterministic precisely because they iterate unsorted
// Go maps when emitting, so that class is avoided deliberately here.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	rbacauthorizer "k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac"
	rbacvalidation "k8s.io/kubernetes/pkg/registry/rbac/validation"
	"sigs.k8s.io/yaml"
)

const toolVersion = "0.1.0"

// store satisfies the four interfaces upstream RBACAuthorizer.New requires. Each is a
// plain lookup over decoded manifests — no cluster client, no informer, no cache.
type store struct {
	roles               map[string]*rbacv1.Role // "namespace/name"
	roleBindings        map[string][]*rbacv1.RoleBinding
	clusterRoles        map[string]*rbacv1.ClusterRole
	clusterRoleBindings []*rbacv1.ClusterRoleBinding
	serviceAccounts     []string // "namespace/name"
	failures            []failure
}

type failure struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
}

func (s *store) GetRole(namespace, name string) (*rbacv1.Role, error) {
	if r, ok := s.roles[namespace+"/"+name]; ok {
		return r, nil
	}
	return nil, fmt.Errorf("role %s/%s not found in the supplied manifests", namespace, name)
}

func (s *store) ListRoleBindings(namespace string) ([]*rbacv1.RoleBinding, error) {
	out := append([]*rbacv1.RoleBinding(nil), s.roleBindings[namespace]...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *store) GetClusterRole(name string) (*rbacv1.ClusterRole, error) {
	if r, ok := s.clusterRoles[name]; ok {
		return r, nil
	}
	return nil, fmt.Errorf("clusterrole %s not found in the supplied manifests", name)
}

func (s *store) ListClusterRoleBindings() ([]*rbacv1.ClusterRoleBinding, error) {
	out := append([]*rbacv1.ClusterRoleBinding(nil), s.clusterRoleBindings...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// splitDocs separates a multi-document YAML stream. Kept explicit rather than using a
// streaming decoder so that one bad document does not discard the rest of the file.
func splitDocs(data []byte) [][]byte {
	parts := strings.Split(string(data), "\n---")
	out := make([][]byte, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, []byte(p))
		}
	}
	return out
}

type typeMeta struct {
	Kind string `json:"kind"`
}

func (s *store) load(path string, rel string) {
	data, err := os.ReadFile(path)
	if err != nil {
		s.failures = append(s.failures, failure{rel, "io_error", err.Error()})
		return
	}
	for i, doc := range splitDocs(data) {
		var tm typeMeta
		if err := yaml.Unmarshal(doc, &tm); err != nil {
			s.failures = append(s.failures, failure{
				rel, "parse_error", fmt.Sprintf("document %d: %v", i, err),
			})
			continue
		}
		switch tm.Kind {
		case "Role":
			var o rbacv1.Role
			if err := yaml.Unmarshal(doc, &o); err != nil {
				s.failures = append(s.failures, failure{rel, "parse_error", err.Error()})
				continue
			}
			s.roles[o.Namespace+"/"+o.Name] = &o
		case "ClusterRole":
			var o rbacv1.ClusterRole
			if err := yaml.Unmarshal(doc, &o); err != nil {
				s.failures = append(s.failures, failure{rel, "parse_error", err.Error()})
				continue
			}
			s.clusterRoles[o.Name] = &o
		case "RoleBinding":
			var o rbacv1.RoleBinding
			if err := yaml.Unmarshal(doc, &o); err != nil {
				s.failures = append(s.failures, failure{rel, "parse_error", err.Error()})
				continue
			}
			s.roleBindings[o.Namespace] = append(s.roleBindings[o.Namespace], &o)
		case "ClusterRoleBinding":
			var o rbacv1.ClusterRoleBinding
			if err := yaml.Unmarshal(doc, &o); err != nil {
				s.failures = append(s.failures, failure{rel, "parse_error", err.Error()})
				continue
			}
			s.clusterRoleBindings = append(s.clusterRoleBindings, &o)
		case "ServiceAccount":
			var o struct {
				Metadata struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"metadata"`
			}
			if err := yaml.Unmarshal(doc, &o); err != nil {
				s.failures = append(s.failures, failure{rel, "parse_error", err.Error()})
				continue
			}
			s.serviceAccounts = append(s.serviceAccounts, o.Metadata.Namespace+"/"+o.Metadata.Name)
		}
	}
}

type decision struct {
	Subject   string `json:"subject"`
	Namespace string `json:"namespace"`
	Verb      string `json:"verb"`
	Group     string `json:"group"`
	Resource  string `json:"resource"`
	Allowed   bool   `json:"allowed"`
	Reason    string `json:"reason"`
}

type output struct {
	Tool             string    `json:"tool"`
	ToolVersion      string    `json:"tool_version"`
	KubernetesModule string    `json:"kubernetes_module_version"`
	Analysed         []string  `json:"analysed"`
	Failed           []failure `json:"failed"`
	ServiceAccounts  []string  `json:"service_accounts"`
	Decisions        []decision `json:"decisions"`
	Note             string    `json:"note"`
}

// probes are the authorization questions asked of every service account. Deliberately
// credential-relevant rather than exhaustive: an exhaustive sweep of the API surface would
// be a different tool.
var probes = []struct{ verb, group, resource string }{
	{"get", "", "secrets"},
	{"list", "", "secrets"},
	{"create", "", "pods"},
	{"get", "", "configmaps"},
	{"list", "", "pods"},
	{"escalate", "rbac.authorization.k8s.io", "clusterroles"},
	{"impersonate", "", "serviceaccounts"},
	{"create", "", "pods/exec"},
}

func main() {
	dir := flag.String("dir", "", "directory of Kubernetes manifests to read (required)")
	ns := flag.String("namespace", "", "restrict probes to this namespace (default: all found)")
	flag.Parse()

	if *dir == "" {
		fmt.Fprintln(os.Stderr, "error: --dir is required. This tool reads manifests from disk; it never contacts a cluster.")
		os.Exit(2)
	}

	s := &store{
		roles:        map[string]*rbacv1.Role{},
		roleBindings: map[string][]*rbacv1.RoleBinding{},
		clusterRoles: map[string]*rbacv1.ClusterRole{},
	}
	var analysed []string
	err := filepath.Walk(*dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			return nil
		}
		rel, _ := filepath.Rel(*dir, p)
		before := len(s.failures)
		s.load(p, rel)
		if len(s.failures) == before {
			analysed = append(analysed, rel)
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error walking %s: %v\n", *dir, err)
		os.Exit(2)
	}

	auth := rbacauthorizer.New(s, s, s, s)

	subjects := append([]string(nil), s.serviceAccounts...)
	sort.Strings(subjects)

	var decisions []decision
	for _, sa := range subjects {
		parts := strings.SplitN(sa, "/", 2)
		if len(parts) != 2 {
			continue
		}
		namespace, name := parts[0], parts[1]
		if *ns != "" && namespace != *ns {
			continue
		}
		u := &user.DefaultInfo{
			Name:   "system:serviceaccount:" + namespace + ":" + name,
			Groups: []string{"system:serviceaccounts", "system:serviceaccounts:" + namespace, "system:authenticated"},
		}
		for _, p := range probes {
			attrs := authorizer.AttributesRecord{
				User:            u,
				Verb:            p.verb,
				Namespace:       namespace,
				APIGroup:        p.group,
				Resource:        p.resource,
				ResourceRequest: true,
			}
			d, reason, err := auth.Authorize(nil, attrs)
			if err != nil {
				reason = reason + " (error: " + err.Error() + ")"
			}
			decisions = append(decisions, decision{
				Subject:   sa,
				Namespace: namespace,
				Verb:      p.verb,
				Group:     p.group,
				Resource:  p.resource,
				Allowed:   d == authorizer.DecisionAllow,
				Reason:    reason,
			})
		}
	}

	// Deterministic emission. Sorted on every key that could otherwise vary.
	sort.Slice(decisions, func(i, j int) bool {
		a, b := decisions[i], decisions[j]
		if a.Subject != b.Subject {
			return a.Subject < b.Subject
		}
		if a.Resource != b.Resource {
			return a.Resource < b.Resource
		}
		return a.Verb < b.Verb
	})
	sort.Strings(analysed)
	sort.Slice(s.failures, func(i, j int) bool { return s.failures[i].Path < s.failures[j].Path })

	if decisions == nil {
		decisions = []decision{}
	}
	if s.failures == nil {
		s.failures = []failure{}
	}
	if analysed == nil {
		analysed = []string{}
	}

	out := output{
		Tool:             "trustlens-rbac",
		ToolVersion:      toolVersion,
		KubernetesModule: kubernetesModuleVersion(),
		Analysed:         analysed,
		Failed:           s.failures,
		ServiceAccounts:  subjects,
		Decisions:        decisions,
		Note: "Decisions come from the upstream Kubernetes RBAC authorizer evaluated over " +
			"the supplied manifests. They establish what these manifests would permit, not " +
			"what any live cluster permits. No cluster was contacted.",
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "error encoding output: %v\n", err)
		os.Exit(2)
	}
	// Exit 1 when anything failed to parse, so a caller reading only the exit code cannot
	// mistake an incomplete evaluation for a complete one.
	if len(s.failures) > 0 {
		os.Exit(1)
	}
}

// kubernetesModuleVersion reports the pinned k8s minor, so the record can show which
// semantics produced a decision.
func kubernetesModuleVersion() string { return "v1.31.4" }

var _ = schema.GroupVersionResource{}
var _ rbacvalidation.RoleGetter = (*store)(nil)
