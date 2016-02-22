import sys
import subprocess
import re

cmdtemp="./run -v {name} -sec {sec} -clr {clr} -rec {rec} -red {red} -repeat {repeat}"

def call(name, sec, clr, rec, red, repeat):
    """
    Return [a,b,c,d] where a is stot, b is son, c is vtot, d is von.
    All are in us.
    """
    cmd = cmdtemp.format(name=name,sec=sec,clr=clr,rec=rec,red=red,repeat=repeat)
    output=subprocess.check_output(
            cmd,
            shell=True,universal_newlines=True)
    print(output)
    return [int(x) for x in re.findall('[0-9]+',output)]


def main():
    name=sys.argv[1]
    sec=int(sys.argv[2])
    clr=int(sys.argv[3])
    rec=int(sys.argv[4])
    red=int(sys.argv[5])

    count_10000t=5

    results=[call(name,sec,clr,rec,red,10000) for _ in range(count_10000t)]
    C1=sum(x[1] for x in results)
    C2=sum(x[2] for x in results)
    C4=sum(x[4] for x in results)
    
    stot=C1/1000/count_10000t #ms/10000t
    son=C2/1000/count_10000t
    vtot=C4/1000/count_10000t
    
    print(stot)
    print(son)
    print(vtot)


if __name__=='__main__':
    main()
