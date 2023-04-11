# YaraCTF
Yaraを用いたCTFの作成

# How To
1. Dockerをインストールする

2. コンテナの作成
    ```
    $ docker-compose up -d
    ```

3. サーバの起動
    まずは、pythonのコンテナに接続
    ```
    $ docker exec -it yaractf bash
    ```

## build
docker上で
```
$ pyinstaller check_yara.py --onefile
```
