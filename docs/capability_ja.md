# Detection Capability

スコア0.8+のFindingで検出できる項目をリストアップします。

| サービス | カテゴリ | データソース | 検知項目 | ドキュメントリンク |
|---|---|---|---|---|
| Cloud KMS | Encryption | cloudsploit | 暗号化キーのパブリックアクセス検出 | [リンク](https://docs.security-hub.jp/google/cloudsploit/) |
| Cloud SQL | Database | cloudsploit | SQLインスタンスのパブリックアクセス検出 | [リンク](https://docs.security-hub.jp/google/cloudsploit/) |
| Cloud Storage | Storage | asset | パブリック＆書き込み可能なバケットの検出 | [リンク](https://docs.security-hub.jp/google/asset/) |
| Compute | Network | portscan | Compute Instancesのパブリックポート開放検出（TCP/UDP） | [リンク](https://docs.security-hub.jp/google/portscan/) |
| Compute | Network | portscan | HTTPオープンプロキシの検出 | [リンク](https://docs.security-hub.jp/google/portscan/) |
| Compute | Network | portscan | SMTPオープンリレーの検出 | [リンク](https://docs.security-hub.jp/google/portscan/) |
| Compute | Network | portscan | SSHパスワード認証有効の検出 | [リンク](https://docs.security-hub.jp/google/portscan/) |
| Compute | Network | portscan | 大量ポート開放の検出（設定された閾値以上のポート範囲） | [リンク](https://docs.security-hub.jp/google/portscan/) |
| Compute | Storage | cloudsploit | パブリックアクセス可能なEBSスナップショット | [リンク](https://docs.security-hub.jp/google/cloudsploit/) |
| Compute | Storage | cloudsploit | パブリックディスクイメージの検出 | [リンク](https://docs.security-hub.jp/google/cloudsploit/) |
| IAM | IAM | asset | 管理者権限を持つService Account(ユーザ管理キー)を検知 | [リンク](https://docs.security-hub.jp/google/asset/) |
| IAM | IAM | cloudsploit | Gmailアカウントの使用検出（企業メールのみの確認） | [リンク](https://docs.security-hub.jp/google/cloudsploit/) |
| Load Balancing | Network | portscan | ForwardingRule（外部ロードバランサー）のポート開放検出 | [リンク](https://docs.security-hub.jp/google/portscan/) |
| Security Command Center | Security | scc | Security Command Centerがサポートしている `CRITICAL` の検出(PremiumやEnterpriseの場合には検出項目が増える) | [リンク](https://docs.security-hub.jp/google/scc/) |
| VPC Network | Firewall | portscan | ファイアウォールルールのパブリック設定検出（0.0.0.0/0からのアクセス） | [リンク](https://docs.security-hub.jp/google/portscan/) |
| VPC Network | Network | cloudsploit | すべてのポート開放の検出（ファイアウォール設定） | [リンク](https://docs.security-hub.jp/google/cloudsploit/) |
