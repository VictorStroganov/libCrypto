# libCrypto
Cryptopro lib for Node.js

0) Создание контейнера и генерация пары закрытого/открытого ключа в хранилище:

/opt/cprocsp/bin/amd64/csptest -keyset -newkeyset -cont '\\.\HDIMAGE\sender-main' -provtype 75 -provider "Crypto-Pro GOST R 34.10-2001 KC1 CSP"

1) Создание запроса на получение сертификата:

/opt/cprocsp/bin/amd64/cryptcp -creatrqst -dn "E=requesteremail@mail.ru, C=RU, CN=localhost, SN=company" -nokeygen -both -ku -cont '\\.\HDIMAGE\sender-main' sender-main.req

2) Отправить запрос:

http://www.cryptopro.ru/certsrv/

3) Получить сертификат

4) Установить сертификат:

/opt/cprocsp/bin/amd64/certmgr -inst -store umy -file sender-main.cer -cont '\\.\HDIMAGE\sender-main'

npm install

eval \`./setenv.sh --64\`

make -f MakeLibCrypto
