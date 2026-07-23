# Corpus selection log (Phase 1)

Enumerated HF datasets by downloads desc via the Hub API; classified by non-recursive tree/main (repo-root files); selected first-qualifying in rank order per the sealed method. Download counts and commit SHAs recorded at selection time (see PRE_REGISTRATION §9 A5 on ranking drift + the non-recursive/root-level fidelity note).

## Selected corpus (verified identity, downloads, pinned SHA)

### Stratum A — code-bearing (repo-root Python)

- **codeparrot/github-code** — downloads 5,701,917, SHA `b5661e6b17396364b2bcf8e68977b0d28e1ebd19`, root .py: ['github-code.py', 'github_preprocessing.py']
- **KakologArchives/KakologArchives** — downloads 1,709,636, SHA `acc47c47da0cc227f4823c99b5dfce7ce213d62a`, root .py: ['KakologArchives.py']
- **k9cli/video-vec2wav2-tokenizer** — downloads 1,371,523, SHA `b6a854a19665f4590568e7ee29bb913953fad0df`, root .py: ['__init__.py', '__main__.py', 'dataset_builder.py', 'main.py', 'pipeline.py', 'statistics.py']
- **HuggingFaceFW/fineweb** — downloads 660,389, SHA `9bb295ddab0e05d785b879661af7260fed5140fc`, root .py: ['lighteval_tasks.py']
- **cais/mmlu** — downloads 453,576, SHA `c30699e8356da336a370243923dbaf21066bb9fe`, root .py: ['hendrycks_test.py']
- **espnet/yodas** — downloads 367,415, SHA `52c5a1b9730a136bfd7c4513d4962c70d4e50530`, root .py: ['meta.py', 'yodas.py']

### Stratum B — passive-data controls (no .py; data verified via recursive tree, §9 A4)

- **anisoleai/fineweb-tokenized** — downloads 8,553,360, SHA `ef1311f460b42138d7a2d18f51e9cc38cedda089`, no .py
- **Benjy/typed_digital_signatures** — downloads 2,376,015, SHA `b2b7e3766c7b1a39430d44b9dbb96e915c819332`, no .py

## Full consideration log (every repo the walk examined, in rank order)

| rank | repo | downloads | decision | reason |
|---|---|---|---|---|
| 1 | anisoleai/fineweb-tokenized | 8,553,360 | include_B | pure-data (no .py) |
| 2 | codeparrot/github-code | 5,701,917 | include_A | code-bearing: py=['github-code.py', 'github_preprocessing.py'] |
| 3 | Benjy/typed_digital_signatures | 2,376,015 | include_B | pure-data (no .py) |
| 4 | huggingface/documentation-images | 2,111,419 | skip_B | not code-bearing; B full or is model |
| 5 | allenai/c4 | 1,753,036 | skip_B | not code-bearing; B full or is model |
| 6 | ksolovev/FineNews | 1,737,703 | skip_B | not code-bearing; B full or is model |
| 7 | hf-doc-build/doc-build-dev | 1,735,874 | skip_B | not code-bearing; B full or is model |
| 8 | KakologArchives/KakologArchives | 1,709,636 | include_A | code-bearing: py=['KakologArchives.py'] |
| 9 | ryanmarten/OpenThoughts-1k-sample | 1,534,979 | skip_B | not code-bearing; B full or is model |
| 10 | hallucinations-leaderboard/results | 1,512,825 | skip_B | not code-bearing; B full or is model |
| 11 | ayuo/hd_tmp | 1,470,692 | skip_B | not code-bearing; B full or is model |
| 12 | Salesforce/wikitext | 1,428,039 | skip_B | not code-bearing; B full or is model |
| 13 | banned-historical-archives/banned-historical-archives | 1,378,543 | skip_B | not code-bearing; B full or is model |
| 14 | k9cli/video-vec2wav2-tokenizer | 1,371,523 | include_A | code-bearing: py=['__init__.py', '__main__.py', 'dataset_builder.py', 'main.py', 'pipeline |
| 15 | m-a-p/FineFineWeb | 1,229,149 | skip_B | not code-bearing; B full or is model |
| 16 | xlangai/ubuntu_osworld_file_cache | 1,181,061 | skip_B | not code-bearing; B full or is model |
| 17 | nvidia/PhysicalAI-Robotics-GR00T-X-Embodiment-Sim | 1,115,290 | skip_B | not code-bearing; B full or is model |
| 18 | openai/gsm8k | 959,558 | skip_B | not code-bearing; B full or is model |
| 19 | HennyPr/ps2_hf2 | 779,856 | skip_B | not code-bearing; B full or is model |
| 20 | XDOF/ABC-130k | 769,724 | exclude | gated=auto disabled=False |
| 21 | genrobot2025/10Kh-RealOmin-OpenData | 741,683 | exclude | gated=auto disabled=False |
| 22 | applied-ai-018/pretraining_v1-omega_books | 711,564 | skip_B | not code-bearing; B full or is model |
| 23 | mvp-lab/LLaVA-OneVision-1.5-Mid-Training-85M | 683,108 | skip_B | not code-bearing; B full or is model |
| 24 | IPEC-COMMUNITY/language_table_lerobot | 678,315 | skip_B | not code-bearing; B full or is model |
| 25 | HuggingFaceFW/fineweb | 660,389 | include_A | code-bearing: py=['lighteval_tasks.py'] |
| 26 | artur-muratov/multilingual-speech-commands-15lang | 636,139 | skip_B | not code-bearing; B full or is model |
| 27 | Maximilians/ps2_hf1 | 602,846 | skip_B | not code-bearing; B full or is model |
| 28 | Kthera/pesoz | 588,573 | skip_B | not code-bearing; B full or is model |
| 29 | mteb/results | 551,797 | skip_B | not code-bearing; B full or is model |
| 30 | jat-project/jat-dataset-tokenized | 544,599 | skip_B | not code-bearing; B full or is model |
| 31 | angie-chen55/python-github-code | 542,264 | skip_B | not code-bearing; B full or is model |
| 32 | Emmyc2/psp | 539,126 | skip_B | not code-bearing; B full or is model |
| 33 | jat-project/jat-dataset | 518,023 | skip_B | not code-bearing; B full or is model |
| 34 | wegrthj/kbcpjv-v654-data | 501,742 | skip_B | not code-bearing; B full or is model |
| 35 | IPEC-COMMUNITY/droid_lerobot | 485,520 | skip_B | not code-bearing; B full or is model |
| 36 | Chelsea707/arxiv-cs-2020-2025-pdfs | 484,819 | skip_B | not code-bearing; B full or is model |
| 37 | WINGNUS/ACL-OCL | 475,005 | skip_B | not code-bearing; B full or is model |
| 38 | princeton-nlp/SWE-bench_Verified | 474,544 | skip_B | not code-bearing; B full or is model |
| 39 | cais/mmlu | 453,576 | include_A | code-bearing: py=['hendrycks_test.py'] |
| 40 | EssentialAI/essential-web-v1.0 | 441,378 | skip_B | not code-bearing; B full or is model |
| 41 | Dagonulca/figofigofigofigo | 440,211 | skip_B | not code-bearing; B full or is model |
| 42 | uoft-cs/cifar10 | 424,611 | skip_B | not code-bearing; B full or is model |
| 43 | allenai/ai2_arc | 410,821 | skip_B | not code-bearing; B full or is model |
| 44 | nyu-mll/glue | 409,623 | skip_B | not code-bearing; B full or is model |
| 45 | mhaamh19/prophet-mosque-library | 387,916 | skip_B | not code-bearing; B full or is model |
| 46 | updatebao/geonamebase_1 | 382,417 | skip_B | not code-bearing; B full or is model |
| 47 | permutans/arxiv-papers-by-subject | 377,260 | skip_B | not code-bearing; B full or is model |
| 48 | cadene/droid_1.0.1 | 374,079 | skip_B | not code-bearing; B full or is model |
| 49 | HuggingFaceFW/fineweb-edu | 372,923 | skip_B | not code-bearing; B full or is model |
| 50 | xlangai/osworld_v2_assets | 369,697 | exclude | gated=auto disabled=False |
| 51 | espnet/yodas | 367,415 | include_A | code-bearing: py=['meta.py', 'yodas.py'] |
