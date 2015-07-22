(** RFC6287 (OCRA)
    @see <http://tools.ietf.org/html/rfc6287> RFC6287
    @see <https://www.rfc-editor.org/errata_search.php?eid=3729> Errata 3729
 *)

open Rresult

(** The abstract OCRA [suite] type *)
type t

type err =
  | Invalid_suite_string

val t_of_string : string -> (t,err) result

val string_of_t : t -> string

(** @return random challenge string [q] with format and length as specified in
    [suite] *)
val challenge : t -> string

(** if timestamp is [`Now], {!gen} and {!verify} will use {!Unix.time} and the
    timestep specified in [suite] to calculate the timestamp value *)
type timestamp = [`Now | `Int64 of int64 ]

(** Generate [OCRA(K, {\[C\] | Q | \[P | S | T\]})].
    @return OCRA Response
    @param c DataInput C: Counter
    @param p DataInput P: Pin Hash
    @param s DataInput S: Session
    @param t DataInput T: Timestamp
    @param key CryptoFunction key K
    @param q DataInput Q: Challenge
*)
val gen: ?c:int64 ->
  ?p:Cstruct.t ->
  ?s:Cstruct.t ->
  ?t:timestamp ->
  key:Cstruct.t -> q:string -> t -> Cstruct.t

(** Verify OCRA Response.
    @return {ul
    {- [(true, None)] upon successful verification for [suite] without
       [C] DataInput}
    {- [(true, Some next_counter)] upon successful verification for [suite]
       with [C] DataInput}
    {- [(false, None)] if verification failed}}
    @param c DataInput C: Counter
    @param p DataInput P: Pin Hash
    @param s DataInput S: Session
    @param t DataInput T: Timestamp
    @param cw Counter Window
    @param tw Timestamp Window
    @param key CryptoFunction key K
    @param q DataInput Q: Challenge
    @param a Response to check against
*)
val verify: ?c:int64 ->
  ?p:Cstruct.t ->
  ?s:Cstruct.t ->
  ?t:timestamp ->
  ?cw:int ->
  ?tw:int ->
  key:Cstruct.t -> q:string -> a:Cstruct.t -> t -> bool * int64 option
