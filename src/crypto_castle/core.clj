(ns crypto-castle.core
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


(defn set-provider
  "Sets the java security provider to bouncy"
  []
  (do 
    (Security/addProvider (new BouncyCastleProvider))
    (PGPUtil/setDefaultProvider "BC")))