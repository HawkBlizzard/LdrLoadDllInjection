  ## 概要
  LdrLoadDll関数を直接呼び出しによるDLLインジェクションです。  
  構造体を使って書き込む手法が一般的ですが、不安定だったのでアセンブリスタブを使って実装しました。
  
## 注意
本実装は技術的な理解を目的としており、エラーチェックやクリーンアップ処理を省略しています。   
ハンドルやメモリがリークする可能性があります。
