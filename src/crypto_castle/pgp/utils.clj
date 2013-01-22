(ns crypto-castle.pgp.utils)

(defn ring-iter
  ""
  [function pubring]
  (map function pubring))