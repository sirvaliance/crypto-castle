(ns crypto-castle.pgp.keyring
  (:import
    (java.security Security)
    (java.io FileInputStream)
    (org.bouncycastle.jce.provider BouncyCastleProvider)
    (org.bouncycastle.util.encoders Hex)
    (org.bouncycastle.bcpg PublicKeyAlgorithmTags)
    (org.bouncycastle.openpgp PGPUtil
                              PGPPublicKey
                              PGPPublicKeyRing
                              PGPPublicKeyRingCollection))
  (:use [clj-time.coerce :only [from-date]]))


(defn get-keyrings
  "Parse a pubring.gpg file and return an iterator of keyrings"
  [pubring-file]
  (iterator-seq 
    (.getKeyRings 
      (new PGPPublicKeyRingCollection 
           (PGPUtil/getDecoderStream 
             (new FileInputStream pubring-file))))))


(defn cast-pubkey 
  "Take a public keyring and cast the key"
  [^PGPPublicKey keyring]
  (.getPublicKey keyring))


(defn get-public-keys 
  "Returns an iterator of public keys"
  [pubring-file]
  (map cast-pubkey (get-keyrings pubring-file)))
