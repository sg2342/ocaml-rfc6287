## ocaml-rfc6287

OCaml implementation of [RFC6287](http://tools.ietf.org/html/rfc6287) OCRA (OATH Challenge-Response Algorithm)
incl. [RFC Errata ID: 3729](https://www.rfc-editor.org/errata_search.php?rfc=6287)

work in progress

## Notes on bisect and ounit tests

```
CONFIGUREFLAGS="--enable-tests --enable-coverage" make distclean cover_test
```