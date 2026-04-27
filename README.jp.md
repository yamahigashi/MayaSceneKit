# maya-scene-kit

`maya-scene-kit` は、Maya ランタイムを必要とせずに Maya シーンファイル
（`.mb` / `.ma`）を調査、監査、変換、書き換えるためのオープンソースツールキットです。

`maya-scene-kit` では、次のような作業を行えます。

- Maya で開く前に、未知の Maya シーンを確認する
- script node や実行可能なシーン要素を監査する
- GUI でフォルダを読み込み、audit 結果や参照パスをまとめて確認する
- `.ma` / `.mb` から file、reference、texture、cache などのパスを抽出する
- clean、path replacement、path-owner deletion、`.mb` から `.ma` への変換を
  段階的に適用し、結果を保存する
- Python ツールやバッチ処理に、シーンを開く前の検査を組み込む


3 つの利用形態があります。

- 対話的な確認と段階的編集のための GUI
- バッチ検査と自動化のための CLI
- 他ツールへシーン検査を組み込むための Python バインディング

![Image](docs/assets/Screenshot_71.png)

## 現在の制約

- `clean` と `replace` は、CLI / GUI ともに現在 `forensic` モードでのみ動作します
- これらは調査や一時的な対処を目的とした機能であり、 **書き換え結果が安全かつ完全に検証済みであることを保証するものではありません**
- `audit` は保守的に判定します。coverage 不足、unknown semantics、parse budget、
  degraded validation がある場合、audit profile に応じて review または deny になります

関連ドキュメント:

- [English README](README.md)
- [Python usage](docs/python_usage.md)
- [Advanced usage](docs/advanced_usage.md)
- [Development](docs/development.md)
- [スタジオ固有の Maya node 情報の注入・外挿](docs/node_info_authoring.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)

## クイックスタート

GUI と CLI は同じリリースアーカイブに含まれます。GitHub Releases から利用 OS
向けのアーカイブをダウンロードして展開してください。

1. Releases ページを開く
2. 利用プラットフォーム向けの `maya-scene-kit` アーカイブをダウンロードする
3. 任意の場所に展開する

### GUI

例:

```powershell
maya-scene-kit-gui.exe
```

GUI はフォルダを読み込み、解析結果を確認し、それらを段階的に編集・破棄し、
結果を保存できます。

GUI には Overview、Audit、Paths、Log タブがあります。フォルダスキャン、
ワークスペース行のフィルタ、audit detail の表示、clean、path-owner deletion、
path replacement 操作の stage、Maya ASCII への変換、既存ファイルへ保存するときの
backup 作成、選択ファイルまたは dirty file 全体の保存を行えます。

#### GUI の典型的な使い方

GUI は、対話的なシーントリアージと段階的な書き換え作業向けです。

1. フォルダを開き `Auto` を有効にしスキャンする
2. `Audit` タブより結果を確認し、必要に応じて clean 操作を stage する
3. `Paths` タブより参照パスを確認し、置換や各種操作を実行する
4. ワークスペース一覧で dirty file を確認し、選択ファイルまたは全変更を保存する

### CLI

例:

```powershell
maya-scene-kit.exe --help


Standalone utilities for Maya scene files (.mb/.ma).

Usage: maya-scene-kit <COMMAND>

Commands:
  inspect   Inspect Maya Binary chunk structure
  dump      Dump requires + script nodes from file or directory
  paths     Extract file/reference paths from file or directory
  audit     Audit execution surfaces with built-in policy and optional literal markers
  to-ascii  Convert Maya Binary (.mb) scenes to Maya ASCII (.ma)
  clean     Remove script nodes and save in forensic mode
  replace   Replace file/reference paths in scene files in forensic mode
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

#### CLI の典型的な使い方

信頼できないシーンや未知のシーンでは、まず `audit` か `dump` から始めてください。
inspect を用いることで、`.mb` ファイルの chunk 構造をさらに追跡調査できます。
replace や clean は、書き換え結果を予測できない場合、使用しないようにしてください。
インタラクティブな書き換えには GUI を使用することをお勧めします。

代表的なコマンド:

```bash
maya-scene-kit audit input.mb
maya-scene-kit dump input.mb --out /tmp/scene_dump.txt
maya-scene-kit paths input.mb --kind reference --json
maya-scene-kit inspect input.mb --max-depth 2
maya-scene-kit to-ascii input.mb output.ma --issues-json /tmp/issues.json
maya-scene-kit clean input.mb output_clean.mb
maya-scene-kit replace input.mb --rule "V:/dcc=X:/dcc" --out output.mb
```


### Python

Python バインディングは GitHub Releases からリリース済み wheel をダウンロードして直接インストールできます。
pip を用いる方法、あるいは zip から展開して通常の Python パッケージとして手動で配置する方法があります。

```powershell
uv pip install --system .\maya_scene_kit-*.whl
```

簡単な import 確認:

```powershell
python -c "import maya_scene_kit; print('maya_scene_kit ok')"
```

Maya から使用する実践例と API 詳細は [docs/python_usage.md](docs/python_usage.md) を参照してください。
ソースビルドや editable install は [docs/development.md](docs/development.md) を参照してください。

#### Python の典型的な使い方

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
`dump_scripts`、`preview_clean`、`clean`、`preview_replace`、`replace`、`to_ascii` があります。

---

CLI のコマンド概要、実行モード、現在のスコープ、runtime `--node-info`
オーバーレイについては [docs/advanced_usage.md](docs/advanced_usage.md) を参照してください。
スタジオ固有の Maya node 情報の注入・外挿については [docs/node_info_authoring.md](docs/node_info_authoring.md) を参照してください。
