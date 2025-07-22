# Detection Capability

スコア0.8+(デフォルトアラート)のFindingで検出できる項目をリストアップします。

| カテゴリ | サービス | データソース | 検知項目 | ドキュメントリンク |
|---|---|---|---|---|
| Database | Cloud SQL | cloudsploit | SQLインスタンスのパブリックアクセス検出 | [リンク](https://docs.security-hub.jp/google/cloudsploit/) |
| IAM | IAM | asset | 管理者権限を持つService Account(ユーザ管理キー)を検知 | [リンク](https://docs.security-hub.jp/google/asset/) |
| IAM | IAM | cloudsploit | Gmailアカウントの使用検出（企業メールのみの確認） | [リンク](https://docs.security-hub.jp/google/cloudsploit/) |
| Key Management | Cloud KMS | cloudsploit | 暗号化キーのパブリックアクセス検出 | [リンク](https://docs.security-hub.jp/google/cloudsploit/) |
| Network | Compute Engine | portscan | HTTPオープンプロキシの検出(有効なFirewall Rules) | [リンク](https://docs.security-hub.jp/google/portscan/) |
| Network | Compute Engine | portscan | SMTPオープンリレーの検出(有効なFirewall Rules) | [リンク](https://docs.security-hub.jp/google/portscan/) |
| Network | Compute Engine | portscan | SSHパスワード認証有効の検出(有効なFirewall Rules) | [リンク](https://docs.security-hub.jp/google/portscan/) |
| Network | Compute Engine | portscan | 大量ポート開放の検出（設定された閾値以上のポート範囲） | [リンク](https://docs.security-hub.jp/google/portscan/) |
| Network | Kubernetes Engine | portscan | HTTPオープンプロキシの検出(有効なFirewall Rules) | [リンク](https://docs.security-hub.jp/google/portscan/) |
| Network | Kubernetes Engine | portscan | SMTPオープンリレーの検出(有効なFirewall Rules) | [リンク](https://docs.security-hub.jp/google/portscan/) |
| Network | Kubernetes Engine | portscan | SSHパスワード認証有効の検出(有効なFirewall Rules) | [リンク](https://docs.security-hub.jp/google/portscan/) |
| Network | Kubernetes Engine | portscan | 大量ポート開放の検出（設定された閾値以上のポート範囲） | [リンク](https://docs.security-hub.jp/google/portscan/) |
| Network | Load Balancer | portscan | HTTPオープンプロキシの検出(有効なFirewall Rules) | [リンク](https://docs.security-hub.jp/google/portscan/) |
| Network | Load Balancer | portscan | SMTPオープンリレーの検出(有効なFirewall Rules) | [リンク](https://docs.security-hub.jp/google/portscan/) |
| Network | Load Balancer | portscan | 大量ポート開放の検出（設定された閾値以上のポート範囲） | [リンク](https://docs.security-hub.jp/google/portscan/) |
| Security | Security Command Center | scc | Security Command Centerがサポートしている `CRITICAL` の脅威検出(PremiumやEnterpriseの場合には検出項目が増える) | [リンク](https://docs.security-hub.jp/google/scc/) |
| Storage | Cloud Storage | asset | パブリック＆書き込み可能なバケットの検出 | [リンク](https://docs.security-hub.jp/google/asset/) |
| Storage | Compute | cloudsploit | パブリックアクセス可能なEBSスナップショット | [リンク](https://docs.security-hub.jp/google/cloudsploit/) |
| Storage | Compute | cloudsploit | パブリックディスクイメージの検出 | [リンク](https://docs.security-hub.jp/google/cloudsploit/) |
