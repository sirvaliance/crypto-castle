(ns crypto-castle.pgp-test
  (:use clojure.test
        crypto-castle.pgp.key
        crypto-castle.pgp.keyring))


(def test-keyring "test-files/pubring.gpg")

(defn keyring-fixture
  [f]
  (let [pkr (get-public-keys test-keyring)]
    (f pkr))
  
(deftest import-keyring
  (testing "Imports the test keyring, checks if there is a single key"
    (is (= 1 (count (get-public-keys test-keyring))))))



(deftest key-search
         (testing "Search pgp.mit.edu for key, parse it, output data"


;; (parse-key (retrieve-key "Sir Valiance"))
