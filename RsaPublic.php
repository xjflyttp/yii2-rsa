<?php

namespace xj\rsa;

use Yii;
use yii\base\Object;

class RsaPublic extends Object {

    /**
     * Certificate
     * @var string
     * @see http://cn2.php.net/manual/en/function.openssl-pkey-get-public.php
     */
    public $key;

    /**
     * Key Pass
     * @var string
     * @see http://cn2.php.net/manual/en/function.openssl-pkey-get-public.php
     */
    public $passphrase = '';

    /**
     * Factory
     * @param string $key KeyPath | KeyContent
     * @param string $passphrase
     * @return RsaPublic
     * @throws \yii\base\Exception
     */
    public static function model($key, $passphrase = '') {
        if (substr($key, 0, 1) === '@') {
            $key = 'file://' . Yii::getAlias($key);
        }
        return new static([
            'key' => $key,
            'passphrase' => $passphrase,
        ]);
    }

    public function __construct($config = array()) {
        parent::__construct($config);
    }

    /**
     * getPrivateKey
     * @return resource|FALSE
     * @see http://cn2.php.net/manual/en/function.openssl-get-publickey.php
     */
    private function getKey() {
        return openssl_pkey_get_public($this->key);
    }

    /**
     * getBits
     * @return int
     */
    private function getCertBits() {
        $detail = openssl_pkey_get_details($this->getKey());
        return (isset($detail['bits'])) ? $detail['bits'] : null;
    }

    private function getCertChars() {
        $certLength = $this->getCertBits();
        return $certLength / 8;
    }

    private function getMaxEncryptCharSize() {
        return $this->getCertChars() - 11;
    }

    /**
     * encrypt
     * @param string $data
     * @return string|null
     * @see http://cn2.php.net/manual/en/function.openssl-public-encrypt.php
     */
    public function encrypt($data) {
        $maxlength = $this->getMaxEncryptCharSize();
        $output = '';
        while ($data) {
            $input = substr($data, 0, $maxlength);
            $data = substr($data, $maxlength);
            $encrypted = '';
            $result = openssl_public_encrypt($input, $encrypted, $this->getKey());
            if ($result === false) {
                return null;
            }
            $output.=$encrypted;
        }
        return base64_encode($output);
    }

    /**
     * decrypt
     * @param string $data
     * @return string|null
     * @see http://cn2.php.net/manual/en/function.openssl-public-decrypt.php
     */
    public function decrypt($data) {
        $maxlength = $this->getCertChars();
        $output = '';
        $data = base64_decode($data);
        while ($data) {
            $input = substr($data, 0, $maxlength);
            $data = substr($data, $maxlength);
            $decrypted = '';
            $result = openssl_public_decrypt($input, $decrypted, $this->getKey());
            if ($result === false) {
                return null;
            }
            $output.=$decrypted;
        }
        return $output;
    }

}
