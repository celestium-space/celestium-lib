#!/bin/sh
par_res=0
sin_res=0
len=100
bits=25
for i in $(seq 1 $len)
do
  random="$(dd if=/dev/urandom bs=1 count=66)"

  start=$(( $(date '+%s%N') / 1000000))
  ./pow-solver $bits $random > /dev/null 2>&1
  end=$(( $(date '+%s%N') / 1000000))

  sin_res=$((sin_res + (end-start)))
  echo "Sin lap $((i)): $((end-start))ms"

  start=$(( $(date '+%s%N') / 1000000))
  ./pow-solver-multi-thread $bits $random > /dev/null 2>&1
  end=$(( $(date '+%s%N') / 1000000))

  par_res=$((par_res + (end-start)))
  echo "Par lap $((i)): $((end-start))ms"
done
echo "Sin sec: $((sin_res/$len))ms"
echo "Par sec: $((par_res/$len))ms"
