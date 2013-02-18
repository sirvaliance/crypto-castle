;; This file is for managing your public key ring
;;
;; Functions this file should contain:
;;
;; x Parsing and returning a PGP keyring from a pubring.gpg file
;; x Adding  a users public keyring to the main keyring collection
;; - Removing ^
;; x Loading/Saving Public keyring files to disk
;; x Return a clojure data structure of keys for easy reading of key info with key.clj
;; - Return a set of public keys from a keyring

(ns crypto-castle.pgp.keyring
  (:import
    (java.security Security)
    (java.io FileInputStream )
    (org.bouncycastle.jce.provider BouncyCastleProvider)
    (org.bouncycastle.util.encoders Hex)
    (org.bouncycastle.bcpg PublicKeyAlgorithmTags)
    (org.bouncycastle.openpgp PGPUtil
                              PGPPublicKey
                              PGPPublicKeyRing
                              PGPPublicKeyRingCollection))
  (:require [clojure.java.io])
  (:use [clj-time.coerce :only [from-date]]))


(defn load-keyring-collection
  "Parse a pubring.gpg file and returns a PGPKeyRingCollection"
  [pubring-file]
  (new PGPPublicKeyRingCollection 
       (PGPUtil/getDecoderStream 
         (new FileInputStream pubring-file))))

(defn save-keyring-collection
  "Saves a PGPKeyRingCollection to a file"
  [pubring-collection pubring-file]
  (with-open [w (clojure.java.io/output-stream pubring-file)]
    (.encode pubring-collection w)))

(defn get-keyrings
  ""
  [pubring-collection]
  (iterator-seq
    (.getKeyRings pubring-collection)))


(defn cast-pubkey 
  "Take a public keyring and cast the key"
  [^PGPPublicKey keyring]
  (.getPublicKey keyring))


(defn get-public-keys 
  "Returns an iterator of public keys"
  [pubring-file]
  (map cast-pubkey (get-keyrings 
                     (load-keyring-collection pubring-file))))

(defn add-public-keyring
  "Adds a public keyring (PGPPublicKeyRing) to a Collection"
  [pubring-collection pub-keyring]
  (PGPPublicKeyRingCollection/addPublicKeyRing pubring-collection pub-keyring))
