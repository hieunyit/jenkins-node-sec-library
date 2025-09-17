#!/usr/bin/awk -f
BEGIN{IGNORECASE=1}
toupper($1)=="FROM"{
  count++
  img=""; stg=""
  for(i=2;i<=NF;i++){
    t=$i
    if (t ~ /^--platform=/) continue
    if (toupper(t)=="AS"){ if (i+1<=NF) stg=$(i+1); break }
    if (img=="") img=t
  }
  if (stg!="") stages[tolower(stg)]=1
  if (img!="") {
    if (!(tolower(img) in stages)) {
      if (first_external=="") first_external=img
      last_external=img
    }
    last_any=img
  }
}
END{
  if (count<=1) print (first_external!=""?first_external:last_any);
  else print (last_external!=""?last_external:last_any);
}
