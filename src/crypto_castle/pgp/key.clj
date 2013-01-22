(ns crypto-castle.pgp.key
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

(defn key-get-id
  ""
  [pubkey]
  (Long/toHexString (.getKeyID pubkey)))

(defn key-get-fingerprint
  ""
  [pubkey]
  (apply str (map char (Hex/encode (.getFingerprint pubkey)))))

(defn algo-string-id
  "Return a string representation of the algorithm name"
  [algo-id]
  (cond 
    (= PublicKeyAlgorithmTags/RSA_GENERAL algo-id) "RSA_GENERAL"
    (= PublicKeyAlgorithmTags/RSA_ENCRYPT algo-id) "RSA_ENCRYPT"
    (= PublicKeyAlgorithmTags/RSA_SIGN algo-id) "RSA_SIGN"
    (= PublicKeyAlgorithmTags/ELGAMAL_ENCRYPT algo-id) "ELGAMAL_ENCRYPT"
    (= PublicKeyAlgorithmTags/DSA algo-id) "DSA"
    (= PublicKeyAlgorithmTags/EC algo-id) "EC"
    (= PublicKeyAlgorithmTags/ECDSA algo-id) "ECDSA"
    (= PublicKeyAlgorithmTags/ELGAMAL_GENERAL algo-id) "ELGAMAL_GENERAL"
    (= PublicKeyAlgorithmTags/DIFFIE_HELLMAN algo-id) "DIFFIE_HELLMAN"
    :else "Algorithm N/A"))

(defn key-get-algorithm
  "Identify what algorithm the key uses"
  [pubkey]
  (.getAlgorithm pubkey))

(defn key-get-algorithm-string
  "Return a string rep of the algorithm from a key"
  [pubkey]
  (algo-string-id (key-get-algorithm pubkey)))

(defn key-get-bit-strength
  ""
  [pubkey]
  (.getBitStrength pubkey))

(defn key-get-creation-time
  ""
  [pubkey]
  (from-date
   (.getCreationTime pubkey)))

(defn get-user-ids
  ""
  [pubkey]
  (.getUserIDs pubkey))

(defn key-get-user-id
  "Return strings of user ids with a key"
  [pubkey]
   (iterator-seq (get-user-ids pubkey)))

(defn get-key-info
  ""
  [pubkey]
  (hash-map
    :user-ids (key-get-user-id pubkey)
    :fingerprint (key-get-fingerprint pubkey)
    :id (key-get-id pubkey)
    :algorithm (key-get-algorithm-string pubkey)))

