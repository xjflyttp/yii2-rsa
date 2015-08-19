yii2-rsa
========

composer.json
-----
```json
"require": {
    "xj/yii2-rsa": "*"
},
```

Rsa
----
```
openssl genrsa -out rsa_private_key.pem 2048
openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem
```

example:
-----
```php
use xj\rsa\RsaPrivate;
use xj\rsa\RsaPublic;

//init
$privateKey = '@common/config/key-private.php';
$publicKey = '@common/config/key-public.php';
$str = 'yii2-rsa';

//private encrypt -> public decrypt
$privateEncryptString = RsaPrivate::model($privateKey)->encrypt($str);
$publicDecryptString = RsaPublic::model($publicKey)->decrypt($privateEncryptString);
var_dump('private', $str, $privateEncryptString, $publicDecryptString);

//public encrypt -> private decrypt
$publicEncryptString = RsaPublic::model($publicKey)->encrypt($str);
$privateDecryptString = RsaPrivate::model($privateKey)->decrypt($publicEncryptString);
var_dump('public', $str, $publicEncryptString, $privateDecryptString);
```