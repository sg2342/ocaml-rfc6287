(** RFC6287 (OCRA) *)

(** The abstract OCRA (suite) type *)
type t

val t_of_string : string -> t option

val string_of_t : t -> string

val challenge : t -> string

exception DataInputError
val gen: ?c:int64 option -> ?p:Cstruct.t option -> ?s:Cstruct.t option -> ?t:int64 option -> suite:t -> key:Cstruct.t -> q:string -> Cstruct.t
