## ocaml-rfc6287

OCaml implementation of [RFC6287](http://tools.ietf.org/html/rfc6287) OCRA (OATH Challenge-Response Algorithm)

work in progress

## Notes on bisect and ounit tests

```
make distclean
./configure --enable-tests --enable-coverage
make
rm -rf bisect*.out report_dir/*
ocaml setup.ml -test -runner sequential
make report
```

point browser at `report_dir/index.html`, observe coverage for `lib/rfc6287.ml`