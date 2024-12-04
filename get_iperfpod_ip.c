#include <stdio.h>

unsigned int ip_to_u32(char *ip_address) {
    unsigned int result = 0;
    unsigned int octet[4]={0};
    sscanf(ip_address, "%d.%d.%d.%d", &octet[0], &octet[1], &octet[2], &octet[3]);
    result = octet[0] + (octet[1] << 8) + (octet[2] << 16) + (octet[3] << 24);
    return result;
}

void Add_to_header(char *str,char *ip_name, char *mode){
    unsigned int result = ip_to_u32(str);
    // printf("%u, %s\n", result, str);
    FILE *headfile=fopen("iperfpod_IP_Address.h", mode);
    if (headfile!=NULL){
        fprintf(headfile, "static const unsigned int %s = %u;\n", ip_name, result);
    }
    fclose(headfile);
}

int main(void)
{
    FILE *pod1 = NULL, *pod2 = NULL;
    pod1 = popen("sudo kubectl get pod -A -owide |grep 'iperf3-server' |grep 'larry125' |awk 'NR==1{print $(NF-3)}' ", "r");
    if(pod1) {  
        char buf[15]={0};
        int ret =  fread(buf, 1, sizeof(buf)-1, pod1);
        if(ret > 0) {
            Add_to_header(buf,"pod1_ip", "w");
        }
        pclose(pod1);
    }

    pod2 = popen("sudo kubectl get pod -A -owide |grep 'iperf3-server' |grep 'larry126' |awk 'NR==1{print $(NF-3)}' ", "r");
    if(pod2) {
        char buf[15]={0};
        int ret =  fread(buf, 1, sizeof(buf)-1, pod2);
        if(ret > 0) {
            Add_to_header(buf, "pod2_ip", "a");
        }
        pclose(pod2);
    }

	return 0;
}
