(ns crypto-castle.pgp.search
  (:import 
    (java.net URL)
    (java.net URLEncoder)
    (java.io ByteArrayInputStream)
    (org.bouncycastle.openpgp PGPUtil
                              PGPObjectFactory))
  (:use [net.cgrand.enlive-html]))

(def keyserver-key-url "http://pgp.mit.edu:11371/pks/lookup?")

(defn build-search-url
  "Returns a url (as a string) encoded with the search parameters"
  [base-url params]
  (str base-url
       "search="
       (URLEncoder/encode params "UTF-8")))


(defn retrieve-key
  "Returns a string"
  [search-term]
  ;; Should url format the string and append to search
  (-> 
    (str (build-search-url keyserver-key-url search-term) "&op=get")
    URL. 
    html-resource 
    (select [:body :pre])
    first
    (get :content)
    first))


(defn parse-key
  "Returns a PGP Key from a string of a pgp object"
  [key-string]
  (iterator-seq
    (.getPublicKeys
      (.nextObject
        (new PGPObjectFactory
             (PGPUtil/getDecoderStream
               (new ByteArrayInputStream
                    (.getBytes key-string))))))))
