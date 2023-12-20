#!/bin/bash

function strip_code()
{
    if [ -z $1 ]; then
        echo "should input file"
        return
    fi

    sed -i 's/[ \t]*$//g' $1
    sed -i "s/\t/    /" $1
}



for line in `find -name "*.c"`
do
    echo "-->strip $line"
    strip_code $line
done

for line in `find -name "*.h"`
do
    echo "-->strip $line"
    strip_code $line
done

