#!/usr/bin/awk -f
BEGIN{IGNORECASE=1}

function handleFrom(line,    parts, n, i, t, img, stg) {
  n = split(line, parts, /[ \t]+/)
  count++
  img=""; stg=""
  for (i=2; i<=n; i++) {
    t = parts[i]
    if (t == "") continue
    if (t ~ /^--platform=/) continue
    if (toupper(t)=="AS") {
      if (i+1<=n) stg=parts[i+1]
      break
    }
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

toupper($1)=="FROM"{
  line = $0
  while (line ~ /\\\s*$/) {
    sub(/\\\s*$/, "", line)
    if (getline nextLine <= 0) break
    line = line " " nextLine
  }
  handleFrom(line)
}

END{
  if (count<=1) print (first_external!=""?first_external:last_any)
  else print (last_external!=""?last_external:last_any)
}
