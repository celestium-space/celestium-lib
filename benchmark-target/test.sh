#!/bin/sh
par_res=0
sin_res=0
for i in 0 1 2 3 4 5 6 7 8 9
do
  random="$(dd if=/dev/urandom bs=1 count=66)"

  start=$(( $(date '+%s%N') / 1000000))
  ./pow-solver 28 $random > /dev/null 2>&1
  end=$(( $(date '+%s%N') / 1000000))

  sin_res=$((sin_res + (end-start)))
  echo "Sin lap $((i)): $((end-start))ms"

  start=$(( $(date '+%s%N') / 1000000))
  ./pow-solver-multi-thread 28 $random > /dev/null 2>&1
  end=$(( $(date '+%s%N') / 1000000))

  par_res=$((par_res + (end-start)))
  echo "Par lap $((i)): $((end-start))ms"
done
echo "Sin sec: $((sin_res/10))ms"
echo "Par sec: $((par_res/10))ms"
