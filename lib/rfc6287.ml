
type dgst = [ `SHA1 | `SHA256 | `SHA512 ]

type cf = { alg : dgst ;
            trunc : int option }

type di = { c : bool ;
            q : ([`A | `N | `H] * int) ;
            p : dgst option ;
            s : int option ;
            t : ([`H | `M | `S] * int) option }

type t = { cf : cf ;
           di : di * string }

exception ParseError
let t_of_string suitestring =
  let open Stringext in

  let die() = raise ParseError in

  let num l mi ma =
    let rec aux l acc =
      match l with
      | [] when acc >= mi && acc <= ma -> acc
      | n::tl when n >= '0' && n <= '9' ->
        aux tl ((acc * 10) + (int_of_char n - int_of_char '0'))
      | _ -> die() in
    aux l 0 in

  let dgst = function
    | "SHA1" -> `SHA1
    | "SHA256" -> `SHA256
    | "SHA512" -> `SHA512
    | _ -> die() in

  let datainput s =
    let hms = function
      | 'H' -> (`H, 48) | 'M' -> (`M, 59) | 'S' -> (`S, 59) | _ -> die() in
    let timestep = function
      | (y, []) -> (y, None)
      | (y, h::[]) -> (y, (match to_list h with
          | ['T';x1;s] -> let hms, _ = hms s in
            Some (hms, num [x1] 1 9)
          | ['T';x1;x2;s] -> let hms, max = hms s in
            Some (hms, num [x1;x2] 1 max)
          | _ -> die()))
      | _ -> die() in
    let session = function
      | (y, []) -> ((y, None), [])
      | (y, h::t) -> (match to_list h with
          | ['S';x1;x2;x3]  -> ((y, (Some (num [x1;x2;x3] 0 999))), t)
          | _ -> ((y, None), h::t)) in
    let pinhash = function
      | (y, []) -> ((y, None), [])
      | (y, h::t) -> (match to_list h with
          | 'P'::_ -> ((y, (Some (dgst (string_after h 1)))), t)
          | _ -> ((y, None), h::t)) in
    let nah = function | 'N' -> `N | 'A' -> `A | 'H' -> `H | _ -> die() in
    let questions = function
      | (y, h::t) -> ((y, (match to_list h with
          | ['Q';s;x1;x2] -> nah s, (num [x1;x2] 4 64) | _ -> die())), t)
      | _ -> die() in
    let counter = function
      | [] -> die()
      | h::t when h = "C" -> (true, t)
      | xs -> (false, xs) in
    let (|>) x f = f x in
    let ((((c,q),p),s),t) =
      split s ~on:'-' |>counter|>questions|>pinhash|>session|>timestep in
    { c = c ; q = q ; p = p ; s = s ; t = t } in

  let cryptofunction s =
    match split s ~on:'-' with
    | ["HOTP"; a; t] ->
      let trunc =
        match num (to_list t) 0 10 with
        | 0 -> None | x when x > 3 -> Some x | _ -> die() in
      { alg = (dgst a) ; trunc = trunc }
    | _ -> raise ParseError in

  try
    let cf_s, di_s = match split suitestring ~on:':' with
      | ["OCRA-1"; c; d] ->  c, d | _ -> die() in
    Some { cf = cryptofunction cf_s ; di = (datainput di_s, suitestring) }
  with ParseError -> None


let string_of_t { cf = _ ; di = (_, s) } = s


let challenge { di = ({ q = (qf, ql); _ }, _); _ } =
  let b = Nocrypto.Rng.generate ql in
  let s = Bytes.create ql in
  let rec aux i m a =
    if i >= ql then () else
      let c = char_of_int (a + (int_of_char (Cstruct.get_char b i)) mod m) in
      Bytes.set s i c;
      aux (i+1) m a in
  match qf with
  | `A -> aux 0 93 33; s
  | `N -> aux 0 10 48; s
  | `H -> (match Hex.of_cstruct b with | `Hex s -> s)


let crypto_function cf key buf =
  let hmac = Nocrypto.Hash.mac cf.alg ~key buf in
  match cf.trunc with
  | None -> hmac
  | Some x ->
    let v = let open Cstruct in
      let o = get_uint8 hmac ((len hmac) - 1) land 0x0f in
      BE.get_uint32 hmac o in
    let s0 = let open Int64 in
      to_string (logand (of_int32 v) 0x7fffffffL) in
    let s1 = let open Bytes in
      match length s0 with
      | n when n > x -> sub s0 (n - x) x
      | n when n < x -> make (x - n) '0' ^ s0
      | _ -> s0 in
    Cstruct.of_string s1

let format_data_input (di, ss) c q p s t =
  let open Cstruct in
  let open Nocrypto in
  let cs_64 i =
    let cs = create 8 in
    BE.set_uint64 cs 0 i; cs in

  (* suite string, 0 terminated *)
  let fss = of_string (ss ^ "\000") in

  (* C, optional *)
  let fc = match (di.c, c) with
    | (false, None) -> create 0
    | (true, Some i) -> cs_64 i
    | _ -> failwith "data input/suite string missmatch (C)" in

  (* Q, mandatory *)
  let fq =
    let hex2bin q =
      let x = match (String.length q) mod 2 with
        | 1 -> q ^ "0"
        | _ -> q in
      Numeric.Z.to_cstruct_be (Z.of_string_base 16 x) in
    let dec2bin q =
      let z = Z.of_string q in
      let s0 = match Hex.of_cstruct (Numeric.Z.to_cstruct_be z) with
        | `Hex "" -> "000"
        | `Hex h -> h in
      let s = match String.get s0 0 with
        | '0' -> String.sub s0 1 ((String.length s0) -1)
        | _ -> s0 in
      hex2bin s in
    let qbuf = create 128 in
    memset qbuf 0;
    let y = match fst(di.q) with
      | `A -> of_string q
      | `N -> dec2bin q
      | `H -> hex2bin q in
    blit y 0 qbuf 0 (len y); qbuf in

  (* P, optional *)
  let fp = match (di.p, p) with
    | (None, None) -> create 0
    | (Some dgst, Some y) when Hash.digest_size dgst = len y -> y
    | _ -> failwith "data input/suite string missmatch (P)" in

  (* S, optional *)
  let fs = match (di.s, s) with
    | (None, None) -> create 0
    | (Some n, Some y) when len y = n -> y
    | _ -> failwith "data input/suite string missmatch (S)" in

  (* T, optional *)
  let ft = match (di.t, t) with
    | (None, None) -> create 0
    | (Some _, Some i) -> cs_64 i
    | _ -> failwith "data input/suite string missmatch (T)" in

  Uncommon.Cs.concat [fss;fc;fq;fp;fs;ft]


let gen ?c ?p ?s ?t ~suite ~key q =
  let buf = format_data_input suite.di c q p s t in
  crypto_function suite.cf key buf


let verify ?c ?p ?s ?t ?cw ~suite ~key q a =
  match (c, cw) with
  | (_, None) ->
    let buf = format_data_input suite.di c q p s t in
    ((crypto_function suite.cf key buf) = a, None)
  | (Some c1, Some cw1) when cw1 > 0 ->
    let ce = Int64.add c1 (Int64.of_int cw1) in
    let buf = format_data_input suite.di c q p s t in
    let c_off = (String.length (snd suite.di)) + 1 in
    let rec loop next =
      match (crypto_function suite.cf key buf) = a with
      | true -> (true, Some next)
      | false when next = ce -> (false, None)
      | false ->
        let _ = Cstruct.BE.set_uint64 buf c_off next in
        loop (Int64.add next 0x01L)
    in
    loop (Int64.add c1 0x01L)
  | _ -> failwith "invalid counter window/no counter in suite"
