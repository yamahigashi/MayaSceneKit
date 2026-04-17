# maya-scene-kit

`maya-scene-kit` は、Maya ランタイムを必要とせずに Maya シーンファイル
（`.mb` / `.ma`）を調査、監査、書き換えるためのオープンソースツールキットです。

`maya-scene-kit` では、次のような作業を行えます。

- Maya で開く前に、未知の Maya シーンを確認する
- script node や実行可能なシーン要素を監査する
- GUI でフォルダを読み込み、audit 結果や参照パスをまとめて確認する
- `.ma` / `.mb` から file、reference、texture、cache などのパスを抽出する
- clean や path replacement の編集を段階的に適用し、結果を保存する
- Python ツールやバッチ処理に、シーンを開く前の検査を組み込む

3経路の利用形態があります。

- 対話的な確認と段階的編集のための GUI
- バッチ検査と自動化のための CLI
- 他ツールへシーン検査を組み込むための Python バインディング

## 提供形態

| 区分 | 主な用途 | 配布形態 |
| --- | --- | --- |
| GUI | 対話的レビューと段階的な clean/replace ワークフロー | リリース成果物 + ソースビルド |
| CLI | バッチ検査、CI、スクリプト実行、リリースバイナリ | GitHub Releases |
| Python | ツール統合と自動化 | リリース成果物 + ソースビルド |
| Rust crates | 内部ワークスペースアーキテクチャ | ソースのみ |

- 公開リリース成果物: CLI、GUI、Python バインディング
- 現在のリポジトリには GUI と Python 向けのソースビルド手順が含まれます
- 内部ソースはまだ安定していません

## 現在の制約

- `clean` と `replace` は、CLI / GUI ともに現在 `forensic` モードでのみ動作します
- これらは調査や一時的な対処を目的とした機能であり、書き換え結果が安全かつ完全に検証済みであることを保証するものではありません

関連ドキュメント:

- [Python usage](docs/python_usage.md)
- [Advanced usage](docs/advanced_usage.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)

## クイックスタート

GUI と CLI は同じリリースアーカイブに含まれます。GitHub Releases から利用 OS
向けのアーカイブをダウンロードして展開してください。

1. Releases ページを開く
2. 利用プラットフォーム向けの `maya-scene-kit` アーカイブをダウンロードする
3. 任意の場所に展開する

現在のリリースアーカイブには次が含まれます:

- `maya-scene-kit` 実行ファイル
- `maya-scene-kit-gui` 実行ファイル
- 各種ドキュメント

### GUI

例:

```powershell
maya-scene-kit-gui.exe
```

GUI はフォルダを読み込み、解析結果を確認し、それらを段階的に編集・破棄し、
結果を保存できます。

TODO: GUI のスクリーンショットを追加する
TODO: 専用ページを作成する

### CLI

例:

```powershell
maya-scene-kit.exe --help
```

### Python

Python バインディングは `crates/maya-scene-kit-python` にあります。
GitHub Releases からリリース済み wheel をダウンロードして直接インストールできます。

```powershell
uv pip install --system .\maya_scene_kit-0.1.0-*.whl
```

簡単な確認例:

```powershell
python -c "import maya_scene_kit; print(maya_scene_kit.inspect_mb('tests/02/sphere.mb', max_depth=0)['scene_format'])"
```

Maya から使用する実践例、ソースビルド、editable install、他詳細な解説は
[docs/python_usage.md](docs/python_usage.md) を参照してください。

## 典型的なワークフロー

### GUI の典型的な使い方

GUI は、対話的なシーントリアージと段階的な書き換え作業向けです。

1. フォルダを開き `Auto Analyse` を有効にしスキャンする
2. `Audit` タブより結果を確認し、必要に応じて clean（検疫）を実行する
3. `Paths` タブより参照パスを確認し、置換や各種操作を実行する
4. 変更を保存する

### Python の典型的な使い方

Python バインディングを用いることで、Maya 本体でファイルを open や import
する前に検査を行うことが可能です。

これは現在の API 構成の上に構築した運用パターンであり、
専用のコールバック API ではありません。

```python
from maya_scene_kit import audit

report = audit("scene.mb", max_preview=120)

if report["blocked_on_uncertainty"]:
    raise RuntimeError("scene requires manual review before open")

if report["disposition"] not in {"allow", "allow_with_notice"}:
    raise RuntimeError(f"audit blocked scene: {report['disposition']}")

# Your tool decides what to do next.
# For example: open the file in a DCC, queue it for review, or copy it to a safe area.
```

他の Python エントリポイントとして `inspect_mb`、`collect_paths`、`dump_requires`、
`dump_scripts`、`preview_clean`、`clean`、`preview_replace`、`replace` があります。

### CLI の典型的な使い方

信頼できないシーンや未知のシーンでは、まず `audit` か `dump` から始めてください。
シーンが render setup やその他の初期化のために script node に依存している場合、
それを削除すると挙動が変わる可能性があります。

代表的なコマンド:

```bash
maya-scene-kit audit input.mb
maya-scene-kit dump input.mb --out /tmp/scene_dump.txt
maya-scene-kit paths input.mb --kind reference --json
maya-scene-kit inspect input.mb --max-depth 2
maya-scene-kit clean input.mb output_clean.mb
maya-scene-kit replace input.mb --rule "V:/dcc=X:/dcc" --out output.mb
```

## コマンド概要

```bash
maya-scene-kit <command> [options]
```

現在の CLI コマンド:

- `inspect`: Maya Binary の chunk 構造を調査する
- `dump`: ファイルまたはディレクトリから `requires` と script node をダンプする
- `paths`: ファイルまたはディレクトリから file path と reference path を抽出する。`file`、`psdFileTex`、`movie` などの `fileTextureName` も対象
- `audit`: 実行可能なサーフェスを監査する
- `clean`: script node を削除し、forensic モードで保存する
- `replace`: file path と reference path を forensic モードで置換する

## 実行モード

シーンの変更や判定を行うコマンドは、次の 3 つのモードのいずれかで動作します。

- `strict`: 対象サーフェスが権威的に検証された場合にのみ成功する
- `best-effort`: 部分的な構造化リカバリを許可するが、完全に検証済みとは主張しない
- `forensic`: ヒューリスティックまたは transport-level の処理を許可し、結果が未検証であることを報告する

公開レポートでは、`validation_state` は次のいずれかとして公開されます。

- `validated`
- `partial`
- `unsupported`
- `invalid`
- `copied_unvalidated`

`audit` は設計上、保守的です。

- `.ma` の実行サーフェスは直接監査されます
- `.mb` の strict audit は、バイナリサーフェス抽出が権威的になるまで fail-closed のままです
- autorun Python サーフェス上の parse failure は、strict 対応パスでは保守的に扱われます

## 現在のスコープ

- `.mb` 向けの IFF chunk parsing（`tag / offset / aux / size`）
- `.ma/.mb` 向けの script node の検出、削除、抽出
- `.ma/.mb` 向けの実行サーフェス監査とレポート生成
- `.ma/.mb` 向けの requires 抽出
- `.ma/.mb` 向けの file path と reference path 抽出
- `.ma/.mb` 向けの file path と reference path 書き換え

`--node-info` オーバーレイや `plugin_node_info` 生成を含む
より詳細なリファレンスについては、
[docs/advanced_usage.md](docs/advanced_usage.md) を参照してください。
