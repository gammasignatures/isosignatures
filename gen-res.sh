#!/bin/bash

schemes="ecao ecpv-x ecpv-a eco-p eco-x eco-a"
secs="160 192 224 256 384 521"
repeat=$1
[ -z "$repeat" ] && repeat=10

echo "scheme,sec,clr,rec,red,usrcount,sigcount,s-on,s-tot,v-on,v-tot,"
for scheme in $schemes
do
	for sec in $secs
	do
		for (( i=1; i<=$repeat; i++  ))
		do
			./run -s $scheme -sec $sec
		done
	done
done

