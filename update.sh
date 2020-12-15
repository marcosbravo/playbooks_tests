#!/bin/bash
apt-get update
if [ $? -eq 0 ]
then
 # Get the latest list of security updates and save it within a file
 apt-get update && apt list --upgradable | grep security > /tmp/updates_info.txt
 # Check if /tmp/updates_info.txt is empty
 if [ ! -s "/tmp/updates_info.txt" ]
 then
 
  ##This runs when there are not security updates: 

  echo "No security updates" > /tmp/updates.txt
  echo "{" > /tmp/updates.json
  echo "    \"metadata\":{" >> /tmp/updates.json
  echo "         \"status\": \"No packages to update \"," >> /tmp/updates.json
  echo "         \"reason_status\":\"There are no packages with security updates\" " >> /tmp/updates.json
  echo "     }," >> /tmp/updates.json
  echo "    \"metadata\":{" >> /tmp/updates.json
  echo "         \"machine-hostname\":\"$(hostname)\"," >> /tmp/updates.json
  echo "         \"generation_data_date\":\"$(ls /tmp/ --full-time | grep .json | awk '{print $6,$7}' | awk -F. '{print $1}' )\"" >> /tmp/updates.json
  echo "    }" >> /tmp/updates.json
  echo "}" >> /tmp/updates.json
 else

  ##This runs when there are security updates 

  # Save just the package names within a file
  awk -F / '{ print $1 }' /tmp/updates_info.txt > /tmp/updates.txt
  # Delete it if exists
  if [ -f /tmp/urgency.txt ]
  then
   rm /tmp/urgency.txt
  fi
  # Get priority from the latest changelog with the following format: urgency=urgency
  for pname in `cat /tmp/updates.txt`
  do
   apt-get changelog $pname | grep 'urgency' | head -n 1  >> /tmp/urgency.txt 2>/dev/null
  done
  # Check if already exists a /tmp/urgencies.txt file
  # Delete it if exists
  if [ -f /tmp/urgencies.txt ]
  then
   rm /tmp/urgencies.txt
  fi
  # Get just the urgency from the previous file and save within a new file.
  awk -F = '{ print $2 }' /tmp/urgency.txt > /tmp/urgencies.txt
  # Get the latest changelog for all the packages within a file for every package.
  for cve in `cat /tmp/updates.txt`
  do
   apt-get changelog $cve >> /tmp/$cve.txt 2>/dev/null
  done
  # Get just the latest changelog version and save it within a file for every package.
  for cve in `cat /tmp/updates.txt`
  do
   awk '/^Get:/{flag=1} flag{buf = buf $0 ORS} /^ -- /{flag=0; if(imprimir=1) print buf; buf=""; imprimir=0} flag && /CVE/{imprimir=1}' /tmp/$cve.txt > /tmp/cve_$cve.txt 2>/dev/null
   rm /tmp/$cve.txt
  done
  if [ -f /tmp/releases.txt ]
  then
   rm /tmp/releases.txt
  fi
  for pkg in `cat /tmp/updates.txt`
  do
   apt-cache policy $pkg | awk '/Installed/{flag=1} flag{buf = buf $0 ORS} /Packages/{flag=0; if(imprimir=1) print buf; buf=""; imprimir=0} flag && /http/{imprimir=1}' | grep http | awk '{print $2}' >> /tmp/repo
  done
  # Get a list with all the CVEs with a file for every package.
  for cve in `cat /tmp/updates.txt`
  do
   echo `cat /tmp/cve_$cve.txt | egrep CVE-20[0-2][0-9]-[0-9]*[,]?$ | tr -d " - " |  sed -e 's/^-//'` > /tmp/cves_$cve.txt 2>/dev/null
   echo `cat /tmp/cve_$cve.txt | egrep [A-Z][a-z][a-z], | awk -F "," '{ print $2 }' | awk '{print $3"-"$2"-"$1}'` > /tmp/release_$cve.txt 2>/dev/null
   rm /tmp/cve_$cve.txt
   sed -i 's/Jan/01/g' /tmp/release_$cve.txt
   sed -i 's/Feb/02/g' /tmp/release_$cve.txt
   sed -i 's/Mar/03/g' /tmp/release_$cve.txt
   sed -i 's/Apr/04/g' /tmp/release_$cve.txt
   sed -i 's/May/05/g' /tmp/release_$cve.txt
   sed -i 's/Jun/06/g' /tmp/release_$cve.txt
   sed -i 's/Jul/07/g' /tmp/release_$cve.txt
   sed -i 's/Aug/08/g' /tmp/release_$cve.txt
   sed -i 's/Sep/09/g' /tmp/release_$cve.txt
   sed -i 's/Oct/10/g' /tmp/release_$cve.txt
   sed -i 's/Nov/11/g' /tmp/release_$cve.txt
   sed -i 's/Dec/12/g' /tmp/release_$cve.txt
  done
  # Splitting CVEs in different lines.
  for cve in `cat /tmp/updates.txt`
  do
   echo `cat /tmp/cves_$cve.txt` | awk -F, '{ for (i=1; i<=NF; i++) print $i }' > /tmp/cves_split_$cve.txt
  done
  for release in `cat /tmp/updates.txt`
  do
   echo `cat /tmp/release_$release.txt` >> /tmp/releases.txt
   rm /tmp/release_$release.txt
  done
  # Array with a list of packages, priority and CVEs.
  arr=($(cat /tmp/updates.txt /tmp/urgencies.txt /tmp/releases.txt /tmp/repo))
  # Length of the group. They all should be the same.
  log_arr=($(cat /tmp/updates.txt | wc -l))
  # Max number of iterations
  num=`expr $log_arr - 1`
  for (( i=0; i<=$num; i++ ))
  do
   # Opening curly brace
   if [ $i -eq 0 ]
   then
    echo "{" > /tmp/updates.json
    echo "    \"repositories\":[" >> /tmp/updates.json
    echo "        {" >> /tmp/updates.json
    echo "            \"repository\":\"${arr[$i+$log_arr+$log_arr+$log_arr]}\"," >> /tmp/updates.json
    echo "            \"packages\":[" >> /tmp/updates.json
   fi
   echo "                {" >> /tmp/updates.json
   echo "                    \"name\":\"${arr[$i]}\"," >> /tmp/updates.json
#   echo "                    \"architecture\":\"$(uname -m)\"," >> /tmp/updates.json
   echo "                    \"release_date\":\"${arr[$i+$log_arr+$log_arr]}\"," >> /tmp/updates.json
   echo "                    \"security\":{" >> /tmp/updates.json
   echo "                        \"urgency\":\"${arr[$i+$log_arr]}\"," >> /tmp/updates.json
   echo "                        \"cves\":[" >> /tmp/updates.json
   arr1=($(cat /tmp/cves_split_${arr[$i]}.txt))
   log_arr1=($(cat /tmp/cves_split_${arr[$i]}.txt | wc -l))
   num1=$(expr $log_arr1 - 1)
   if [ ! $log_arr1 -eq 0 ]
   then
    for (( j=0; j<=$num1; j++ ))
    do
     if [ $j -eq $num1 ]
     then
      echo "                            \"${arr1[$j]}\"" >> /tmp/updates.json
      echo "                        ]" >> /tmp/updates.json
      echo "                    }" >> /tmp/updates.json
      if [ ! $i -eq $num ]
      then
       echo "                }," >> /tmp/updates.json
      else
       echo "                }" >> /tmp/updates.json
      fi
     else
      echo "                            \"${arr1[$j]}\"," >> /tmp/updates.json
     fi
    done
   else
    echo "                        ]" >> /tmp/updates.json
    echo "                    }" >> /tmp/updates.json
     if [ ! $i -eq $num ]
     then
      echo "                }," >> /tmp/updates.json
     else
      echo "                }" >> /tmp/updates.json
     fi
   fi
   if [ $i -eq $num ]
   then
    echo "            ]," >> /tmp/updates.json
    echo "            \"metadata\":{" >> /tmp/updates.json
    echo "                \"status\":\"OK\"," >> /tmp/updates.json
    echo "                \"reason_status\":\"There are packages with security updates\"" >> /tmp/updates.json
    echo "            }" >> /tmp/updates.json
    echo "        }" >> /tmp/updates.json
    echo "    ]," >> /tmp/updates.json
    echo "    \"metadata\":{" >> /tmp/updates.json
    echo "        \"machine-hostname\":\"$(hostname)\"," >> /tmp/updates.json
    echo "        \"generation_data_date\":\"$(ls /tmp/ --full-time | grep .json | awk '{print $6,$7}' | awk -F. '{print $1}' )\"" >> /tmp/updates.json
    echo "    }" >> /tmp/updates.json
    echo "}" >> /tmp/updates.json
   fi
  done
  # Replace * if there is in some CVE
  sed -i s/"*CVE/"CVE/g "/tmp/updates.json"
  # Removing temp files
  for cve in `cat /tmp/updates.txt`
  do
   rm /tmp/cves_$cve.txt
   rm /tmp/cves_split_$cve.txt
  done
   rm /tmp/updates_info.txt /tmp/urgency.txt /tmp/urgencies.txt /tmp/releases.txt /tmp/repo
 fi

##If there is an error, the following is executed: 

else
 echo `apt-get update` > /tmp/error_updates.txt
 echo "No security updates" > /tmp/updates.txt
 echo "{" > /tmp/updates.json
 echo "    \"metadata\":{" >> /tmp/updates.json
 echo "         \"status\":\"ERROR\"," >> /tmp/updates.json
 echo "         \"reason_status\":\"`cat /tmp/error_updates.txt`\"" >> /tmp/updates.json 
 echo "    }" >> /tmp/updates.json
 echo "    \"metadata\":{" >> /tmp/updates.json
 echo "         \"machine-hostname\":\"$(hostname)\"," >> /tmp/updates.json
 echo "         \"generation_data_date\":\"$(ls /tmp/ --full-time | grep .json | awk '{print $6,$7}' | awk -F. '{print $1}' )\"" >> /tmp/updates.json
 echo "    }" >> /tmp/updates.json
 echo "}" >> /tmp/updates.json
 rm /tmp/error_updates.txt
fi
