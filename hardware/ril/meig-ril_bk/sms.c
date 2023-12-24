/*SMS*/
/*when who why modified*/

#include <telephony/ril.h>
#include <stdio.h>
#include <ctype.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <alloca.h>
#include <getopt.h>
#include <sys/socket.h>
#include <cutils/sockets.h>
#include <cutils/properties.h>
#include <termios.h>
#include <stdlib.h>

#define LOG_TAG "RIL"
#include "atchannel.h"
#include "at_tok.h"
#include "misc.h"
#include "ril_common.h"
#include "sms.h"
#include "getdevinfo.h"
#include <utils/Log.h>

/*added by zte-yuang  for adding sms_send_report begin */
SMS_Type sms_type =  SMS_GENERAL;
/*added by zte-yuang  for adding sms_send_report end */
extern int cur_oper;
/*[zhaopf@meigsmart-2022/08/23] modify for new version at of sms Begin */
extern MODEM_INFO  curr_modem_info;
/*[zhaopf@meigsmart-2022/08/23] modify for new version at of sms End */

int handover_flag = 0;


#if 1
#define PDU_3GPP_7BIT
#ifdef PDU_3GPP_7BIT
typedef unsigned char uint8;
typedef enum {
    ENCODE_7BIT,
    ENCODE_UNICDE,
    ENCODE_NULL,
} encode_e_type;

typedef struct cdma_7bit_data {
    char data_3pgg2_ptr[500];
    char data_3pgg2_len;
    char data_len;
} cdma_7bit_data_s_type;

cdma_7bit_data_s_type cdma_7bit_d;
//extern unsigned char GetBit(unsigned char uByte, int iBitIndex);
unsigned char GetBit(unsigned char uByte, int iBitIndex);

//extern void SetBit(unsigned char* lpByte, int iBitIndex, unsigned char uVal);
void SetBit(unsigned char* lpByte, int iBitIndex, unsigned char uVal);

// 7bit编码

// 输入: pSrc - 源字符串指针

//       nSrcLength - 源字符串长度

// 输出: pDst - 目标编码串指针

// 返回: 目标编码串长度


int meig_at_cops1(int response[4])
{
    int err;
    ATResponse *p_response = NULL;
    char *line;
    char *oper;

    response[0] = response[1] = response[2] = response[3] = 0;

    err = at_send_command_singleline("AT+COPS=3,2;+COPS?", "+COPS:", &p_response);
    if ((err < 0) ||  (p_response == NULL) || (p_response->success == 0))
        goto error;

    line = p_response->p_intermediates->line;

    err = at_tok_start(&line);
    if (err < 0) goto error;

//+COPS:<mode>[,<format>[,<oper>][,<Act>]]
    err = at_tok_nextint(&line, &response[0]);
    if (err < 0) goto error;

    if (!at_tok_hasmore(&line)) goto error;

    err = at_tok_nextint(&line, &response[1]);
    if (err < 0) goto error;

    if (!at_tok_hasmore(&line)) goto error;

    err = at_tok_nextstr(&line, &oper);
    if (err < 0) goto error;
    response[2] = atoi(oper);

    if (!at_tok_hasmore(&line)) goto error;

    err = at_tok_nextint(&line, &response[3]);
    if (err < 0) goto error;

error:
    at_response_free(p_response);
    return response[3];
}



int Encode7bit(const char* pSrc, unsigned char* pDst, int nSrcLength)

{

    int iDst;

    int nBitsInByte;
    int iSrc;
    int i;


    //unsigned char* szDst = new unsigned char[nSrcLength+1];
    unsigned char  szDst[nSrcLength+1];

    memset(szDst, 0x00, nSrcLength+1);

    iDst = 0;

    nBitsInByte = 0;

    for (iSrc = 0; iSrc < nSrcLength; iSrc++) {
        for (i = 0; i < 7; i++) {
            unsigned char uBitVal = GetBit(*(pSrc+iSrc), i+1);

            SetBit(szDst+iDst, nBitsInByte, uBitVal);

            nBitsInByte++;

            if (nBitsInByte >= 8) {
                nBitsInByte = 0;

                iDst++;
            }
        }
    }

    if (nBitsInByte > 0) {
        iDst++;
    }

    for (i = 0; i < iDst; i++) {
        sprintf((char*)pDst+2*i, "%02x", *(szDst+i));

    }

    //delete szDst;

    //szDst = 0;

    return iDst*2;

}



// 7bit解码

// 输入: pSrc - 源编码串指针

//       nSrcLength - 源编码串长度

// 输出: pDst - 目标字符串指针

// 返回: 目标字符串长度

int Decode7bit(const unsigned char* pSrc, char* pDst, int nSrcLength)
{

    unsigned char uVal;

    int iDst = 0;

    int nBitsInByte = 1;
    int iSrc;
    int i;
    unsigned char uBitVal;




    RLOGD("Decode7bit pSrc = %s nSrcLength = %d!\n\r",pSrc,nSrcLength);

    for ( iSrc = 0; iSrc < nSrcLength; iSrc += 2)

    {



        sscanf((char*)pSrc+iSrc, "%02x", (unsigned int*)&uVal);

        for ( i = 0; i < 8; i++)

        {

            RLOGD("for Decode7bit  uVal = %02x\n\r",(unsigned int)uVal);


            uBitVal = GetBit(uVal, i);


            SetBit((unsigned char*)pDst+iDst, nBitsInByte, uBitVal);

            nBitsInByte++;

            if (nBitsInByte >= 8)

            {

                nBitsInByte = 1;

                iDst++;

            }

        }

    }



    if (nBitsInByte > 0)

    {

        iDst++;

    }

    return iDst;

}



unsigned char GetBit(unsigned char uByte, int iBitIndex)

{

    unsigned char uVal;

    uVal = uByte;

    uVal = uVal & (0x80 >> iBitIndex);

    uVal = uVal >> (7 - iBitIndex);

    return uVal;

}



void SetBit(unsigned char* lpByte, int iBitIndex, unsigned char uVal)

{

    unsigned char uBit = uVal;

    uBit = uBit & 0x01;

    *lpByte = *lpByte | (uBit << (7 - iBitIndex));

}

int gsmEncode7bit(const char* pSrc, unsigned char* pDst, int nSrcLength)
{

    int nSrc;

    // 源字符串的计数值

    int nDst;

    // 目标编码串的计数值

    int nChar;

    //当前正在处理的组内字符字节的序号，范围是0-7
    unsigned char nLeft;
    //上一字节残余的数据

    // 计数值初始化

    nSrc = 0;

    nDst = 0;

    // 将源串每8个字节分为一组，压缩成7个字节

    // 循环该处理过程，直至源串被处理完

    // 如果分组不到8字节，也能正确处理

    while(nSrc<nSrcLength) {

        //取源字符串的计数值的最低3位

        nChar = nSrc & 7;
        //处理源串的每个字节

        if(nChar == 0) {
            //组内第一个字节，只是保存起来，待处理下一个字节时使用

            nLeft = *pSrc;
        } else {
            // 组内其它字节，将其右边部分与残余数据相加，得到一个目标编码字节
            *pDst = (*pSrc << (8-nChar)) | nLeft;

            // 将该字节剩下的左边部分，作为残余数据保存起来
            nLeft = *pSrc >> nChar;

            // 修改目标串的指针和计数值
            pDst++;
            nDst++;
        }

        // 修改源串的指针和计数值

        pSrc++;
        nSrc++;
    }
    // 返回目标串长度
    return nDst;
}
// 7-bit解码
// pSrc: 源编码串指针
// pDst: 目标字符串指针
// nSrcLength: 源编码串长度
// 返回: 目标字符串长度
int gsmDecode7bit(const unsigned char* pSrc, char* pDst, int nSrcLength)
{
    int nSrc;        // 源字符串的计数值
    int nDst;        // 目标解码串的计数值
    int nByte;       // 当前正在处理的组内字节的序号，范围是0-6
    unsigned char nLeft;    // 上一字节残余的数据
    // 计数值初始化
    nSrc = 0;
    nDst = 0;
    // 组内字节序号和残余数据初始化
    nByte = 0;
    nLeft = 0;
    // 将源数据每7个字节分为一组，解压缩成8个字节
    // 循环该处理过程，直至源数据被处理完
    // 如果分组不到7字节，也能正确处理
    while(nSrc<nSrcLength) {
        // 将源字节右边部分与残余数据相加，去掉最高位，得到一个目标解码字节
        *pDst = ((*pSrc << nByte) | nLeft) & 0x7f;
        // 将该字节剩下的左边部分，作为残余数据保存起来
        nLeft = *pSrc >> (7-nByte);
        // 修改目标串的指针和计数值
        pDst++;
        nDst++;
        // 修改字节计数值
        nByte++;
        // 到了一组的最后一个字节
        if(nByte == 7) {
            // 额外得到一个目标解码字节
            *pDst = nLeft;
            // 修改目标串的指针和计数值
            pDst++;
            nDst++;
            // 组内字节序号和残余数据初始化
            nByte = 0;
            nLeft = 0;
        }
        // 修改源串的指针和计数值
        pSrc++;
        nSrc++;
    }
    *pDst = 0;
    // 返回目标串长度
    return nDst;
}

void StrToHex(char *pbDest, char *pbSrc, int nLen)
{
    char h1,h2;
    char s1,s2;
    int i;

    for (i=0; i<nLen; i++) {
        h1 = pbSrc[2*i];
        h2 = pbSrc[2*i+1];

        s1 = toupper(h1) - 0x30;
        if (s1 > 9)
            s1 -= 7;

        s2 = toupper(h2) - 0x30;
        if (s2 > 9)
            s2 -= 7;

        pbDest[i] = s1*16 + s2;
    }
}
//GSM 7bit字符串包转化为数字包
char str_2_num(char* pdu_str_p, char str_len, char* num_buff_p)
{
    char pdu_str[0xff] = {0};
    char num_buff[0xff] = {0};
    char byte_str[3] = {0};
    char num;
    int i = 0; 
    if(str_len > 200) {
        return 0;
    }
    memcpy(pdu_str, pdu_str_p,str_len);
    for(i=0; i<str_len; i++) {
        byte_str[0] = pdu_str_p[i];
        byte_str[1] = pdu_str_p[i+1];
        byte_str[2] = '\0';
        StrToHex(&num, byte_str, 2);
        num_buff[i/2] = num;
    }
    memcpy(num_buff_p,num_buff,str_len/2);
    return str_len/2;
}

//void pdu_3gpp_7bit_2_3gpp2_7bit(char* pdu_data_ptr, char* data_3pgg2_ptr, char* data_3pgg2_len)
void pdu_3gpp_7bit_2_3gpp2_7bit(char* pdu_data_ptr)
{
    char num_buff[255]= {0};
    char num_buff_len = 0;
    char decode_3gpp_str[255] = {0};
    char encode_3gpp2_str[255] = {0};
    char decode_3gpp_str_len = 0;
    char len = 0;
    char encode_3gpp2_hex[255] = {0};
    char encode_3gpp2_hex_len = 0;
    char i;
    num_buff_len = str_2_num(pdu_data_ptr, strlen(pdu_data_ptr), num_buff);
    decode_3gpp_str_len = gsmDecode7bit(num_buff, decode_3gpp_str,num_buff_len);
    len = Encode7bit(decode_3gpp_str, encode_3gpp2_str, strlen(decode_3gpp_str));
    encode_3gpp2_hex_len = str_2_num(encode_3gpp2_str, strlen(encode_3gpp2_str), encode_3gpp2_hex);
    memset(&cdma_7bit_d,0,sizeof(cdma_7bit_data_s_type));
    if((strlen(decode_3gpp_str)%8) == 7) {
        memcpy(cdma_7bit_d.data_3pgg2_ptr,encode_3gpp2_hex,encode_3gpp2_hex_len-1);
        cdma_7bit_d.data_3pgg2_len = encode_3gpp2_hex_len -1;
        cdma_7bit_d.data_len = strlen(decode_3gpp_str);
    } else {
        memcpy(cdma_7bit_d.data_3pgg2_ptr,encode_3gpp2_hex,encode_3gpp2_hex_len);
        cdma_7bit_d.data_3pgg2_len = encode_3gpp2_hex_len;
        cdma_7bit_d.data_len = decode_3gpp_str_len;
    }
}
//extern void converthextostr(char *hex_str,char *dest_str,int hex_str_len);
//extern void convertstrtohex(char *src_str,char *hex_str,int src_str_len);
void converthextostr(char *hex_str,char *dest_str,int hex_str_len);
void convertstrtohex(char *src_str,char *hex_str,int src_str_len);


void pdu_3gpp2_7bit_2_3gpp_7bit(char* hex_3gpp2_ptr,int hex_len, char* pdu_3gpp_str)
{
    char dest_str[500] = {0};
    char decode_3gpp2_str[500] = {0};
    char encode_3gpp_hex[500] = {0};
    int decode_3gpp2_str_len = 0;
    int encode_3gpp_hex_len = 0;
    int encode_3gpp_str_len = 0;

    converthextostr(hex_3gpp2_ptr, dest_str, hex_len);

    RLOGD("cdma_pdu_2_3gpp_pdu dest_str=%s!",dest_str);


    decode_3gpp2_str_len = Decode7bit(dest_str, decode_3gpp2_str, strlen(dest_str));



    if(decode_3gpp2_str_len%8 ==7) {
        int dest_str_len = strlen(dest_str);
        dest_str[dest_str_len] = '0';
        dest_str[dest_str_len+1] = '0';
        dest_str[dest_str_len+2] = '\0';
        memset(decode_3gpp2_str,0,500);
        decode_3gpp2_str_len = Decode7bit(dest_str, decode_3gpp2_str, strlen(dest_str));



    }

    encode_3gpp_hex_len = gsmEncode7bit(decode_3gpp2_str,encode_3gpp_hex,decode_3gpp2_str_len);

    converthextostr(encode_3gpp_hex, pdu_3gpp_str, encode_3gpp_hex_len);

}

void parse_3gpp2_sms(char *src_3gpp2_pdu,char *number,int *dig_num_len,char *time,
                     char *sms_data,uint8 *data_len,uint8 *str_len,encode_e_type* encode_type)
{
    int pos =16;
    int i,j;
    int tmp_len = 0;
    uint8 tmp = 0;
    uint8 hex_tmp[500] = {0};
    if((src_3gpp2_pdu[pos]>='0') && (src_3gpp2_pdu[pos] <= '9')) {
        tmp_len = (src_3gpp2_pdu[pos]-'0')*16;
    } else if((src_3gpp2_pdu[pos]>='a') && (src_3gpp2_pdu[pos] <= 'f')) {
        tmp_len = ((src_3gpp2_pdu[pos]-'a')+10)*16;
    } else if((src_3gpp2_pdu[pos]>='A') && (src_3gpp2_pdu[pos] <= 'F')) {
        tmp_len = ((src_3gpp2_pdu[pos]-'A')+10)*16;
    }
    if((src_3gpp2_pdu[pos+1]>='0') && (src_3gpp2_pdu[pos+1] <= '9')) {
        tmp_len += src_3gpp2_pdu[pos+1]-'0';
    } else if((src_3gpp2_pdu[pos+1]>='a') && (src_3gpp2_pdu[pos+1] <= 'f')) {
        tmp_len += (src_3gpp2_pdu[pos+1]-'a')+10;
    } else if((src_3gpp2_pdu[pos+1]>='A') && (src_3gpp2_pdu[pos+1] <= 'F')) {
        tmp_len += (src_3gpp2_pdu[pos+1]-'A')+10;
    }
    pos += 2;
    memset(hex_tmp,0,500);
    convertstrtohex(&src_3gpp2_pdu[pos],hex_tmp,tmp_len*2);
    *dig_num_len = ((hex_tmp[0]&0x3f)<<2)+((hex_tmp[1]&0xc0)>>6);
    for(i=0,j=0; i<tmp_len; i++,j++) {
        tmp = ((hex_tmp[1+i]&0x3f)<<2) + ((hex_tmp[1+i+1]&0xc0)>>6);
        number[j] = (tmp&0xf0)>>4;
        if(number[j] == 0x0a) {
            number[j] = '0';
        } else {
            number[j] += '0';
        }
        j++;
        if(j >= *dig_num_len)
            break;
        number[j] = tmp&0x0f;
        if(number[j] == 0x0a) {
            number[j] = '0';
        } else {
            number[j] += '0';
        }
    }
    pos += tmp_len*2;
    pos += 22;
    if((src_3gpp2_pdu[pos]>='0') && (src_3gpp2_pdu[pos] <= '9')) {
        tmp_len = (src_3gpp2_pdu[pos]-'0')*16;
    } else if((src_3gpp2_pdu[pos]>='a') && (src_3gpp2_pdu[pos] <= 'f')) {
        tmp_len = ((src_3gpp2_pdu[pos]-'a')+10)*16;
    } else if((src_3gpp2_pdu[pos]>='A') && (src_3gpp2_pdu[pos] <= 'F')) {
        tmp_len = ((src_3gpp2_pdu[pos]-'A')+10)*16;
    }
    if((src_3gpp2_pdu[pos+1]>='0') && (src_3gpp2_pdu[pos+1] <= '9')) {
        tmp_len += src_3gpp2_pdu[pos+1]-'0';
    } else if((src_3gpp2_pdu[pos+1]>='a') && (src_3gpp2_pdu[pos+1] <= 'f')) {
        tmp_len += (src_3gpp2_pdu[pos+1]-'a')+10;
    } else if((src_3gpp2_pdu[pos+1]>='A') && (src_3gpp2_pdu[pos+1] <= 'F')) {
        tmp_len += (src_3gpp2_pdu[pos+1]-'A')+10;
    }
    pos += 2;
    memset(hex_tmp,0,500);
    convertstrtohex(&src_3gpp2_pdu[pos],hex_tmp,tmp_len*2);
    tmp = (hex_tmp[0]&0xf8)>>3;
    switch(tmp) {
    case 0x02:
        *encode_type = ENCODE_7BIT;
        break;
    case 0x04:
        *encode_type = ENCODE_UNICDE;
        break;
    default:
        RLOGD("encode_type = %d err!",*encode_type);
        return;
    }

    *str_len = ((hex_tmp[0]&0x07)<<5) + ((hex_tmp[1]&0xf8)>>3);

    if(ENCODE_7BIT == *encode_type) {
        for(i=0; i<tmp_len; i++) {
            sms_data[i] = ((hex_tmp[1+i]&0x07)<<5) + ((hex_tmp[1+i+1]&0xf8)>>3);
            RLOGD("sms_data[%d]=0x%x!",i,sms_data[i]);
            if((1+i+1) >= tmp_len) {
                *data_len = i+1;
                break;
            }
        }
    } else if(ENCODE_UNICDE == *encode_type) {
        for(i=0; i<tmp_len; i++) {
            sms_data[i] = ((hex_tmp[1+i]&0x07)<<5) + ((hex_tmp[1+i+1]&0xf8)>>3);
            RLOGD("sms_data[%d]=0x%x!",i,sms_data[i]);
            if((1+i+1) >= tmp_len) {
                *data_len = i;
                break;
            }
        }
    }

    pos += tmp_len*2;
    pos += 4;
    memcpy(time,&src_3gpp2_pdu[pos],12);
    return;
}
uint8 encode_3gpp_sms_pdu(char *pdu,char *addr,char* time,
                          uint8 addr_len,char *data,uint8 data_len,uint8 str_len,encode_e_type encode_type)
{
    int pos = 0;
    int i = 0;
    int j = 0;//08 91683108200905F0 040D 91683175420784F2 0000 510121917262 23 0AB0986C46ABD96EB81C
    char data_hex[500] = {0};
    pdu[pos] = 0x08;
    pos++;
    pdu[pos] = 0x91;
    pos++;
    pdu[pos] = 0x68;
    pos++;
    pdu[pos] = 0x31;
    pos++;
    pdu[pos] = 0x08;
    pos++;
    pdu[pos] = 0x20;
    pos++;
    pdu[pos] = 0x09;
    pos++;
    pdu[pos] = 0x05;
    pos++;
    pdu[pos] = 0xF0;
    pos++;
//    if(11 == addr_len)
    {
        pdu[pos] = 0x04;
        pos++;
        pdu[pos] = addr_len+2;
        pos++;
        pdu[pos] = 0x91;
        pos++;
        pdu[pos] = 0x68;
    }
    /*    else
        {
            pdu[pos] = 0x60;
        pos++;
            pdu[pos] = addr_len;
        pos++;
        pdu[pos] = 0xA1;
        }*/
    pos++;
    for(i=0; i<addr_len; i++) {
        if((addr_len%2 != 0) && ((i+1)>=addr_len)) {
            pdu[pos] = 0xF0 + (addr[i]-'0');
        } else {
            pdu[pos] = ((addr[i+1]-'0')<<4) + (addr[i]-'0');
        }
        pos++;
        i = i +1;
    }
    pdu[pos] = 0x00;
    pos++;
    switch(encode_type) {
    case ENCODE_7BIT:
        pdu[pos] = 0x00;
        break;
    case ENCODE_UNICDE:
        pdu[pos] = 0x08;
        break;
    default:
        RLOGD("encode_3gpp_sms_pdu::encode_type err!encode_type=%d",encode_type);
        break;
    }
    pos++;
    //time
    for(i=0; i<12; i++) {
        if((time[i]<'0')||(time[i]<'9')) {
            RLOGD("encode_3gpp_sms_pdu::number err!addr[%d]=%c",i,time[i]);
        }
        pdu[pos] = ((time[i+1]-'0')<<4) + (time[i]-'0');
        pos++;
        i = i+1;
    }
    pdu[pos] = 0x23;
    pos++;
    switch(encode_type) {
    case ENCODE_7BIT:
        pdu[pos] = str_len;
        pos++;
        convertstrtohex(data, data_hex, data_len*2);
        for(i=0; i<data_len; i++) {
            pdu[pos] = data_hex[i];
            pos++;
        }
        break;
    case ENCODE_UNICDE:
        pdu[pos] = data_len;
        pos++;
        for(i=0; i<data_len; i++) {
            pdu[pos] = data[i];
            pos++;
        }
        break;
    default:
        RLOGD("encode_3gpp_sms_pdu::encode_type err!encode_type=%d",encode_type);
        break;
    }
    return pos;
}
void cdma_pdu_2_3gpp_pdu(char *pdu_3gpp2, char *pdu_3gpp)
{
    char number[32] = {0};
    uint8 dig_num_len = 0;
    char time[16] = {0};
    char sms_data[500] = {0};
    char pdu_3gpp_data[500] = {0};
    char pdu_3gpp_hex[500] = {0};
    int pdu_3gpp_hex_len = 0;
    uint8 data_len = 0;
    uint8 str_len = 0;
    uint8 pdu_3gpp_len = 0;
    encode_e_type encode_type = ENCODE_NULL;

    parse_3gpp2_sms(pdu_3gpp2, number,&dig_num_len,time, sms_data,
                    &data_len, &str_len,&encode_type);

    RLOGD("cdma_pdu_2_3gpp_pdu sms_data=%s, encode_type = %d err!",sms_data,encode_type);

    switch(encode_type) {
    case ENCODE_7BIT:
        pdu_3gpp2_7bit_2_3gpp_7bit(sms_data,data_len, pdu_3gpp_data);
        pdu_3gpp_hex_len = encode_3gpp_sms_pdu(pdu_3gpp_hex,number,time,dig_num_len,pdu_3gpp_data,
                                               data_len,str_len,encode_type);
        converthextostr(pdu_3gpp_hex,pdu_3gpp,pdu_3gpp_hex_len);
        pdu_3gpp_len = strlen(pdu_3gpp);
        if(str_len%8 == 7) {
            pdu_3gpp[pdu_3gpp_len] = '0';
            pdu_3gpp[pdu_3gpp_len+1] = '0';
            pdu_3gpp[pdu_3gpp_len+2] = '\0';
        }
        break;
    case ENCODE_UNICDE:
        pdu_3gpp_hex_len = encode_3gpp_sms_pdu(pdu_3gpp_hex,number,time,dig_num_len,sms_data,
                                               data_len,str_len,encode_type);
        converthextostr(pdu_3gpp_hex,pdu_3gpp,pdu_3gpp_hex_len);
        break;
    default:
        RLOGD("cdma_pdu_2_3gpp_pdu encode_type=%d err!",encode_type);
        return;
    }
}
#endif



void convertstrtohex(char *src_str,char *hex_str,int src_str_len)
{
    int i = 0;
    int j = 0;
    if(0 != (src_str_len%2)) {
        src_str_len = src_str_len+1;
    }
    while(j < src_str_len) {
        if((src_str[j] >= '0') && (src_str[j]<='9')) {
            hex_str[i] = (src_str[j]-'0')<<4;
        } else if ((src_str[j] >= 'a') && (src_str[j]<='f')) {
            hex_str[i] = ((src_str[j]-'a')+10)<<4;
        } else if ((src_str[j] >= 'A') && (src_str[j]<='F')) {
            hex_str[i] = ((src_str[j]-'A')+10)<<4;
        }
        j++;
        if((src_str[j] >= '0') && (src_str[j]<='9')) {
            hex_str[i] |= (src_str[j]-'0');
        } else if ((src_str[j] >= 'a') && (src_str[j]<='f')) {
            hex_str[i] |= ((src_str[j]-'a')+10);
        } else if ((src_str[j] >= 'A') && (src_str[j]<='F')) {
            hex_str[i] |= ((src_str[j]-'A')+10);
        }
        i++;
        j++;
    }
}

void converthextostr(char *hex_str,char *dest_str,int hex_str_len)
{
    int i = 0;
    int j = 0;
    char high_4_bit;
    char low_4_bit;
    int dest_str_len = hex_str_len * 2;
    while(i < hex_str_len) {
        high_4_bit = hex_str[i] >> 4;
        low_4_bit = hex_str[i] & 0x0F;
        i++;
        if((high_4_bit >= 0) && (high_4_bit <= 9)) {
            dest_str[j] = high_4_bit + '0';
            j++;
        } else if((high_4_bit >= 0x0A) && (high_4_bit <= 0x0F)) {
            dest_str[j] = (high_4_bit - 10) + 'A';
            j++;
        }

        if((low_4_bit >= 0) && (low_4_bit <= 9)) {
            dest_str[j] = low_4_bit + '0';
            j++;
        } else if((low_4_bit >= 0x0A) && (low_4_bit <= 0x0F)) {
            dest_str[j] = (low_4_bit - 10) + 'A';
            j++;
        }
    }
}

uint8 encode_cdma_sms_pdu_7bit(char *pdu,char *addr,
                               uint8 addr_len,char *data,uint8 data_len,uint8 str_len)
{
    int pos = 0;
    int i = 0;
    int j = 0;
    pdu[pos] = 0x00;
    pos++;
    pdu[pos] = 0x00;
    pos++;
    pdu[pos] = 0x02;
    pos++;
    pdu[pos] = 0x10;
    pos++;
    pdu[pos] = 0x02;
    pos++;
    pdu[pos] = 0x04;
    pos++;
    pdu[pos] = ((addr_len * 4) + 12)/8;
    pos++;
    pdu[pos] = 0x00;
    pdu[pos] |= addr_len>>2;
    pos++;
    pdu[pos] = addr_len<<6;
    while(i < addr_len/2+1) {
        if((addr[i]&0xf0) == 0) {
            addr[i] += 0xa0;
        }
        if((addr[i]&0x0f) == 0) {
            addr[i] += 0x0a;
        }
        //电话号码最后的f 修改
        if(i==addr_len/2) {
            addr[i] &= 0xf0;
        }
        pdu[pos] |= addr[i]>>2;
        pos++;
        pdu[pos] = addr[i]<<6;
        i++;
    }
    //pos++;
    pdu[pos] = 0x06;
    pos++;
    pdu[pos] = 0x01;
    pos++;
    pdu[pos] = 0xFC;
    pos++;
    pdu[pos] = 0x08;
    pos++;
    pdu[pos] = data_len + 9;
    pos++;
    pdu[pos] = 0x00;
    pos++;
    pdu[pos] = 0x03;
    pos++;
    pdu[pos] = 0x20;
    pos++;
    pdu[pos] = 0x00;
    pos++;
    pdu[pos] = 0x00;
    pos++;
    pdu[pos] = 0x01;
    pos++;
    pdu[pos] = data_len + 2;
    pos++;
    pdu[pos] = 0x10;//7bit
    pdu[pos] |= str_len>>5;
    pos++;
    pdu[pos] = (str_len & 0x1F)<<3;
    i = 0;
    while(i<data_len) {
        pdu[pos] |= data[i]>>5;
        pos++;
        pdu[pos] = (data[i] & 0x1F)<<3;
        i++;
    }
    return pos;
}


uint8 encode_cdma_sms_pdu(char *pdu,char *addr,
                          uint8 addr_len,char *data,int data_len)
{
    int pos = 0;
    int i = 0;
    int j = 0;
    char hex_data[200];
    memset(hex_data,0x0,sizeof(hex_data));
    pdu[pos] = 0x00;
    pos++;
    pdu[pos] = 0x00;
    pos++;
    pdu[pos] = 0x02;
    pos++;
    pdu[pos] = 0x10;
    pos++;
    pdu[pos] = 0x02;
    pos++;
    pdu[pos] = 0x04;
    pos++;
    pdu[pos] = ((addr_len * 4) + 12)/8;
    pos++;
    pdu[pos] = 0x00;
    pdu[pos] |= addr_len>>2;
    pos++;
    pdu[pos] = addr_len<<6;
    while(i < addr_len/2+1) {
        if((addr[i]&0xf0) == 0) {
            addr[i] += 0xa0;
        }
        if((addr[i]&0x0f) == 0) {
            addr[i] += 0x0a;
        }
        //电话号码最后的f 修改
        if(i==addr_len/2) {
            addr[i] &= 0xf0;
        }
        pdu[pos] |= addr[i]>>2;
        pos++;
        pdu[pos] = addr[i]<<6;
        i++;
    }

    //pos++;
    pdu[pos] = 0x06;
    pos++;
    pdu[pos] = 0x01;
    pos++;
    pdu[pos] = 0xFC;
    pos++;
    pdu[pos] = 0x08;
    pos++;
    pdu[pos] = data_len + 9;
    pos++;
    pdu[pos] = 0x00;
    pos++;
    pdu[pos] = 0x03;
    pos++;
    pdu[pos] = 0x20;
    pos++;
    pdu[pos] = 0x00;
    pos++;
    pdu[pos] = 0x00;
    pos++;
    pdu[pos] = 0x01;
    pos++;
    pdu[pos] = data_len + 2;
    pos++;
    //设置编码格式
    pdu[pos] = 0x20;
    //传入得是字符个数，转成unicode个数，判断有几个unicode字符
    pdu[pos] |= (data_len/2)>>5;
    pos++;
    pdu[pos] = ((data_len/2) & 0x1F)<<3;
    convertstrtohex(data,hex_data,data_len*2);
    i = 0;
    while(i<data_len+1) {
        pdu[pos] |= hex_data[i]>>5;
        pos++;
        pdu[pos] = (hex_data[i] & 0x1F)<<3;
        i++;
    }
    return pos;
}

//add sms 7bit

int odm_convert_serialize_to_numbers(const char* psrc, char* pdst, int nsrclength)
{
    int ndstlength;
    char ch;

    ndstlength = nsrclength;
    int i;
    if ((psrc == NULL) || (pdst == NULL))
        return -1;
    // 两两颠倒
    for(i=0; i<nsrclength; i+=2) {
        ch = *psrc++;         // 保存先出现的字符
        *pdst++ = *psrc++;     // 复制后出现的字符
        *pdst++ = ch;         // 复制先出现的字符
    }

    // 最后的字符是'F'吗？
    if(*(pdst-1) == 'F') {
        pdst--;
        ndstlength--;         // 目标字符串长度减1
    }

    // 输出字符串加个结束符
    *pdst = '\0';

    // 返回目标字符串长度
    return ndstlength;
}


void parse_3gpp_sms(char *src_3gpp_pdu,char *number,uint8 *num_len,int *dig_num_len,
                    char *sms_data,uint8 *data_len,int *dig_data_len,encode_e_type* encode_type)
{
    int pos =6;
    int i = 0;
    RLOGD("src_3gpp_pdu = %s",src_3gpp_pdu);
    if((src_3gpp_pdu[pos]>='0') && (src_3gpp_pdu[pos] <= '9')) {
        *dig_num_len = (src_3gpp_pdu[pos]-'0')*16;
    } else if((src_3gpp_pdu[pos]>='a') && (src_3gpp_pdu[pos] <= 'f')) {
        *dig_num_len = ((src_3gpp_pdu[pos]-'a')+10)*16;
    }
    if((src_3gpp_pdu[pos+1]>='0') && (src_3gpp_pdu[pos+1] <= '9')) {
        *dig_num_len += src_3gpp_pdu[pos+1]-'0';
    } else if((src_3gpp_pdu[pos+1]>='a') && (src_3gpp_pdu[pos+1] <= 'f')) {
        *dig_num_len += (src_3gpp_pdu[pos+1]-'a')+10;
    }
    convertstrtohex(&src_3gpp_pdu[6],num_len,2);
    pos = pos+4;



    /*
        if((*dig_num_len%2) != 0)  //调整奇偶性
          *dig_num_len+=1;

        *dig_num_len=odm_convert_serialize_to_numbers(src_3gpp_pdu[pos], number,*dig_num_len);
    */


    while(i<*dig_num_len)

    {
        number[i] = src_3gpp_pdu[pos+1];
        number[i+1] = src_3gpp_pdu[pos];
        i= i+2;
        pos = pos+2;



//debug
//        RLOGD("wangbo i= %d, number[i] = %d",i, number[i]);
//        RLOGD("wangbo i= %d, number[i] = %x",i, number[i]);

    }



//wangbo add for gsm 7bit wrong phone number
    /*

        if(( number[*dig_num_len] == 'F') || (number[*dig_num_len] == 'f') )
        {
            number[*dig_num_len]='\0';
        }
    */
//end
    pos = pos+3;
    if('0' == src_3gpp_pdu[pos]) {
        *encode_type = ENCODE_7BIT;
    } else if('8' == src_3gpp_pdu[pos]) {
        *encode_type = ENCODE_UNICDE;
    } else {
        RLOGD("PDU encode type err!");
        *encode_type = ENCODE_NULL;
    }
    pos = pos+1;
    if((src_3gpp_pdu[pos]>='0') && (src_3gpp_pdu[pos] <= '9')) {
        *dig_data_len = (src_3gpp_pdu[pos]-'0')*16;
    } else if((src_3gpp_pdu[pos]>='a') && (src_3gpp_pdu[pos] <= 'f')) {
        *dig_data_len = ((src_3gpp_pdu[pos]-'a')+10)*16;
    }
    if((src_3gpp_pdu[pos+1]>='0') && (src_3gpp_pdu[pos+1] <= '9')) {
        *dig_data_len += src_3gpp_pdu[pos+1]-'0';
    } else if((src_3gpp_pdu[pos+1]>='a') && (src_3gpp_pdu[pos+1] <= 'f')) {
        *dig_data_len += (src_3gpp_pdu[pos+1]-'a')+10;
    }
    convertstrtohex(&src_3gpp_pdu[pos],data_len,2);

    pos= pos+2;
    i = 0;
    while(i<(*dig_data_len*2)) {
        sms_data[i] = src_3gpp_pdu[pos];
        i++;
        pos++;
    }
}
#endif
/*
request functions

**/





/*
request functions

**/
void requestSendSMS( void* data, size_t datalen, RIL_Token t )
{
    int err;
    const char* smsc;
    const char* pdu;
    int tpLayerLength;
    char* cmd1, *cmd2;
    RIL_SMS_Response response;
    ATResponse* p_response = NULL;
    int send_retry = 0;


    int cops_response[4] = {0};


#if 1
//wangbo debug
    //char phone_number[12];
    char phone_number[16];
    char dst_3gpp2_pdu[500];
    char hex_3gpp2_pdu[300];
    char sms_data[250];
    char hex_phone_num[6];
    uint8 phone_num_len = 0;
    int dig_num_len = 0;
    uint8 dst_3gpp2_pdu_len = 0;
    uint8 sms_data_len = 0;
    int dig_sms_data_len = 0;
    encode_e_type encode_type = ENCODE_NULL;
    uint8 i;
    memset(phone_number,0x0,sizeof(phone_number));
    memset(dst_3gpp2_pdu,0x0,sizeof(dst_3gpp2_pdu));
    memset(sms_data,0x0,sizeof(sms_data));
    memset(hex_3gpp2_pdu,0x0,sizeof(hex_3gpp2_pdu));
    memset(hex_phone_num,0x0,sizeof(hex_phone_num));
#endif

    smsc = ( ( const char** )data )[0];
    pdu = ( ( const char** )data )[1];
    tpLayerLength = strlen( pdu ) / 2;
    // "NULL for default SMSC"
    if ( smsc == NULL ) {
        smsc = "00";
    }
    asprintf( &cmd2, "%s%s", smsc, pdu );
    // if ((ODM_CT_OPERATOR_3G == cur_oper) ||(ODM_CT_OPERATOR_4G == cur_oper))

    err = meig_at_cops1(cops_response);

/*[zhaopf@meigsmart-2022/08/23] modify for new version at of sms Begin */
    if ( curr_modem_info.info.at_version != AT_VERSION_2 && ((8 == cops_response[3]) ||( 9 == cops_response[3]) ||(10 == cops_response[3]) || (46011 == cops_response[2]) )
/*yufeilong modify for SLM770A cannot send sms 20230404 begin*/
        && curr_modem_info.info.sltn_type != ASR) {
/*yufeilong modify for SLM770A cannot send sms 20230404 end*/
/*[zhaopf@meigsmart-2022/08/23] modify for new version at of sms End */



        //wangbo 2017/07/12 add for cdma sms
#if 0
        int net_type=0;
        net_type =odm_get_current_network_type();
        if(14 == odm_get_current_network_type()) {
            //at_send_command("AT+MODODR=9",NULL);
            at_send_command("AT+MODODR=8",NULL);
            handover_flag = 1;
#if 0
            while(6 != odm_get_current_network_type()
                    && 7!= odm_get_current_network_type()
                    && 13!= odm_get_current_network_type()
                    && 10> send_retry)
#endif
                net_type =odm_get_current_network_type();
            while(6 != net_type
                    && 7!= net_type
                    && 13!= net_type
                    && 10> send_retry) {
                sleep(1);
                send_retry++;
                RLOGD("send_retry = %d",send_retry);
                net_type =odm_get_current_network_type();
            }
        }
#endif

        parse_3gpp_sms(cmd2,phone_number,&phone_num_len,&dig_num_len,
                       sms_data,&sms_data_len,&dig_sms_data_len,&encode_type);

//debug wangbo
        //RLOGD("wangbo debug sms_data = %s",sms_data);
        //RLOGD("wangbo phone_number = %s",phone_number);
        //RLOGD("wangbo encode_type = %d",encode_type);

        //RLOGD("wangbo phone_num_len = %d",phone_num_len);
        //RLOGD("wangbo dig_num_len = %d",dig_num_len);





        convertstrtohex(phone_number,hex_phone_num,dig_num_len);

        //debug wangbo
        //RLOGD("wangbo hex_phone_num = %d",hex_phone_num);

        if(ENCODE_7BIT == encode_type) {
            pdu_3gpp_7bit_2_3gpp2_7bit(sms_data);

            dst_3gpp2_pdu_len = encode_cdma_sms_pdu_7bit(hex_3gpp2_pdu,hex_phone_num,phone_num_len,
                                cdma_7bit_d.data_3pgg2_ptr,cdma_7bit_d.data_3pgg2_len,cdma_7bit_d.data_len);

            converthextostr(hex_3gpp2_pdu,dst_3gpp2_pdu,dst_3gpp2_pdu_len+1);
            tpLayerLength = strlen( dst_3gpp2_pdu ) / 2;
        } else if(ENCODE_UNICDE == encode_type) {

            dst_3gpp2_pdu_len = encode_cdma_sms_pdu(hex_3gpp2_pdu,hex_phone_num,phone_num_len,
                                                    sms_data,sms_data_len);
            converthextostr(hex_3gpp2_pdu,dst_3gpp2_pdu,dst_3gpp2_pdu_len);

            tpLayerLength = strlen( dst_3gpp2_pdu ) / 2;
        }

        asprintf(&cmd1,"AT^HCMGS=%d",tpLayerLength);

        asprintf(&cmd2,"%s",dst_3gpp2_pdu);
        err = at_send_command_sms( cmd1, cmd2, "^HCMGS:", &p_response );
    } else {
        asprintf( &cmd1, "AT+CMGS=%d", tpLayerLength );
        err = at_send_command_sms( cmd1, cmd2, "+CMGS:", &p_response );
    }
    RLOGD("err=%d,p_response->sucess=%d",err,p_response->success);
    if ( err != 0 || p_response->success == 0 ) {
        //goto error;
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
        at_response_free( p_response );
        return;
    }

    memset( &response, 0, sizeof( response ) );
    /* FIXME fill in messageRef and ackPDU */
    RIL_onRequestComplete( t, RIL_E_SUCCESS, &response, sizeof( response ) );
    at_response_free( p_response );
    return;
    /*
    error:
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);

    at_response_free(p_response);
    */
}



#if 0

void requestSendSMS( void* data, size_t datalen, RIL_Token t )
{
    int err;
    const char* smsc;
    const char* pdu;
    int tpLayerLength;
    char* cmd1, *cmd2;
    RIL_SMS_Response response;
    ATResponse* p_response = NULL;
    int send_retry = 0;

    int cops_response[4] = {0};



#if 1
//wangbo debug
    char phone_number[12];
    //char phone_number[16];
    char dst_3gpp2_pdu[500];
    char hex_3gpp2_pdu[300];
    char sms_data[250];
    char hex_phone_num[6];
    uint8 phone_num_len = 0;
    int dig_num_len = 0;
    uint8 dst_3gpp2_pdu_len = 0;
    uint8 sms_data_len = 0;
    int dig_sms_data_len = 0;
    encode_e_type encode_type = ENCODE_NULL;
    uint8 i;
    memset(phone_number,0x0,sizeof(phone_number));
    memset(dst_3gpp2_pdu,0x0,sizeof(dst_3gpp2_pdu));
    memset(sms_data,0x0,sizeof(sms_data));
    memset(hex_3gpp2_pdu,0x0,sizeof(hex_3gpp2_pdu));
    memset(hex_phone_num,0x0,sizeof(hex_phone_num));
#endif

    smsc = ( ( const char** )data )[0];
    pdu = ( ( const char** )data )[1];
    tpLayerLength = strlen( pdu ) / 2;
    // "NULL for default SMSC"
    if ( smsc == NULL ) {
        smsc = "00";
    }
    asprintf( &cmd2, "%s%s", smsc, pdu );

#if 1 //
    parse_3gpp_sms(cmd2,phone_number,&phone_num_len,&dig_num_len,
                   sms_data,&sms_data_len,&dig_sms_data_len,&encode_type);

//debug wangbo
    RLOGD("wangbo debug sms_data = %s",sms_data);
    RLOGD("wangbo phone_number = %s",phone_number);
    RLOGD("wangbo encode_type = %d",encode_type);

    RLOGD("wangbo phone_num_len = %d",phone_num_len);
    RLOGD("wangbo dig_num_len = %d",dig_num_len);





    convertstrtohex(phone_number,hex_phone_num,dig_num_len);

    //debug wangbo
    RLOGD("wangbo hex_phone_num = %d",hex_phone_num);

    if(ENCODE_7BIT == encode_type) {
        pdu_3gpp_7bit_2_3gpp2_7bit(sms_data);

        dst_3gpp2_pdu_len = encode_cdma_sms_pdu_7bit(hex_3gpp2_pdu,hex_phone_num,phone_num_len,
                            cdma_7bit_d.data_3pgg2_ptr,cdma_7bit_d.data_3pgg2_len,cdma_7bit_d.data_len);

        converthextostr(hex_3gpp2_pdu,dst_3gpp2_pdu,dst_3gpp2_pdu_len+1);
        tpLayerLength = strlen( dst_3gpp2_pdu ) / 2;
    } else if(ENCODE_UNICDE == encode_type) {

        dst_3gpp2_pdu_len = encode_cdma_sms_pdu(hex_3gpp2_pdu,hex_phone_num,phone_num_len,
                                                sms_data,sms_data_len);
        converthextostr(hex_3gpp2_pdu,dst_3gpp2_pdu,dst_3gpp2_pdu_len);

        tpLayerLength = strlen( dst_3gpp2_pdu ) / 2;
    }
#endif

    err = meig_at_cops1(cops_response);


    if ( (8 == cops_response[3]) ||( 9 == cops_response[3]) ||(10 == cops_response[3]) || (46011 == cops_response[2]) ) {



        asprintf(&cmd1,"AT^HCMGS=%d",tpLayerLength);

        asprintf(&cmd2,"%s",dst_3gpp2_pdu);

        RLOGD("wangbo 3gpp2 tPLayerLength = %d, cmd1= %s,cmd2= %s",tpLayerLength, cmd1, cmd2);

        err = at_send_command_sms( cmd1, cmd2, "^HCMGS:", &p_response );


        RLOGD("err=%d,p_response->sucess=%d",err,p_response->success);
        if ( err != 0 || p_response->success == 0 ) {
            //goto error;
            RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
            at_response_free( p_response );
            return;
        }


    } else {

        asprintf( &cmd1, "AT+CMGS=%d", tpLayerLength );

        asprintf(&cmd2,"%s",dst_3gpp2_pdu);

        RLOGD("wangbo 3gpp tPLayerLength = %d, cmd1= %s,cmd2= %s",tpLayerLength, cmd1, cmd2);
        err = at_send_command_sms( cmd1, cmd2, "+CMGS:", &p_response );
        //err = at_send_command_sms( cmd1, cmd2, "+CMGS:", &p_response );
        //err = at_send_command_sms( cmd3, cmd4, "+CMGS:", &p_response );

        RLOGD("err=%d,p_response->sucess=%d",err,p_response->success);
        if ( err != 0 || p_response->success == 0 ) {
            //goto error;
            RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
            at_response_free( p_response );
            return;
        }

    }
    memset( &response, 0, sizeof( response ) );
    /* FIXME fill in messageRef and ackPDU */
    RIL_onRequestComplete( t, RIL_E_SUCCESS, &response, sizeof( response ) );
    at_response_free( p_response );
    return;
    /*
    error:
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);

    at_response_free(p_response);
    */
}

#endif


#if 0
void requestSendSMS(void *data, size_t datalen, RIL_Token t)
{
    int err;
    const char *smsc;
    const char *pdu;
    int tpLayerLength;
    char *cmd1 = NULL, *cmd2 = NULL;
    RIL_SMS_Response response;
    ATResponse *p_response = NULL;


#if 1
    //wangbo debug
    char phone_number[12];
    //char phone_number[16];
    char dst_3gpp2_pdu[500];
    char hex_3gpp2_pdu[300];
    char sms_data[250];
    char hex_phone_num[6];
    uint8 phone_num_len = 0;
    int dig_num_len = 0;
    uint8 dst_3gpp2_pdu_len = 0;
    uint8 sms_data_len = 0;
    int dig_sms_data_len = 0;
    encode_e_type encode_type = ENCODE_NULL;
    uint8 i;
    memset(phone_number,0x0,sizeof(phone_number));
    memset(dst_3gpp2_pdu,0x0,sizeof(dst_3gpp2_pdu));
    memset(sms_data,0x0,sizeof(sms_data));
    memset(hex_3gpp2_pdu,0x0,sizeof(hex_3gpp2_pdu));
    memset(hex_phone_num,0x0,sizeof(hex_phone_num));
#endif



    smsc = ((const char **)data)[0];
    pdu = ((const char **)data)[1];

    tpLayerLength = strlen(pdu)/2;

    // "NULL for default SMSC"
    if (smsc == NULL) {
        smsc= "00";
    }

    asprintf( &cmd2, "%s%s", smsc, pdu );


#if 1 //
    parse_3gpp_sms(cmd2,phone_number,&phone_num_len,&dig_num_len,
                   sms_data,&sms_data_len,&dig_sms_data_len,&encode_type);

    //debug wangbo
    RLOGD("wangbo debug sms_data = %s",sms_data);
    RLOGD("wangbo phone_number = %s",phone_number);
    RLOGD("wangbo encode_type = %d",encode_type);

    RLOGD("wangbo phone_num_len = %d",phone_num_len);
    RLOGD("wangbo dig_num_len = %d",dig_num_len);





    convertstrtohex(phone_number,hex_phone_num,dig_num_len);

    //debug wangbo
    RLOGD("wangbo hex_phone_num = %d",hex_phone_num);

    if(ENCODE_7BIT == encode_type) {
        pdu_3gpp_7bit_2_3gpp2_7bit(sms_data);

        dst_3gpp2_pdu_len = encode_cdma_sms_pdu_7bit(hex_3gpp2_pdu,hex_phone_num,phone_num_len,
                            cdma_7bit_d.data_3pgg2_ptr,cdma_7bit_d.data_3pgg2_len,cdma_7bit_d.data_len);

        converthextostr(hex_3gpp2_pdu,dst_3gpp2_pdu,dst_3gpp2_pdu_len+1);
        tpLayerLength = strlen( dst_3gpp2_pdu ) / 2;
    } else if(ENCODE_UNICDE == encode_type) {

        dst_3gpp2_pdu_len = encode_cdma_sms_pdu(hex_3gpp2_pdu,hex_phone_num,phone_num_len,
                                                sms_data,sms_data_len);
        converthextostr(hex_3gpp2_pdu,dst_3gpp2_pdu,dst_3gpp2_pdu_len);

        tpLayerLength = strlen( dst_3gpp2_pdu ) / 2;
    }
#endif



    asprintf(&cmd1, "AT+CMGS=%d", tpLayerLength);
    //asprintf(&cmd2, "%s%s", smsc, pdu);
    asprintf(&cmd2,"%s",dst_3gpp2_pdu);


    err = at_send_command_sms(cmd1, cmd2, "+CMGS:", &p_response);
    free(cmd1);
    free(cmd2);

    if (err != 0 || p_response->success == 0) goto error;

    memset(&response, 0, sizeof(response));

    /* FIXME fill in messageRef and ackPDU */

    RIL_onRequestComplete(t, RIL_E_SUCCESS, &response, sizeof(response));
    at_response_free(p_response);

    return;
error:
    RLOGD("%s error", __func__);
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
}
#endif


void requestSendCDMASMS( void* data, size_t datalen, RIL_Token t )
{
    int err;
    const char* pdu;
    int tpLayerLength;
    const char* smsc;
    char* cmd1, *cmd2;
    RIL_SMS_Response response;
    ATResponse* p_response = NULL;
    RLOGD("CMDA data = %s,datalen=%d",data,datalen);
#if 0
    smsc = ( ( const char** )data )[0];
    pdu = ( ( const char** )data )[1];
    tpLayerLength = strlen( pdu ) / 2;
    // "NULL for default SMSC"
    if ( smsc == NULL ) {
        smsc = "00";
    }

    asprintf( &cmd2, "%s%s", smsc, pdu );
    err = at_send_command_sms( cmd1, cmd2, "^HCMGS:", &p_response );
    if ( err != 0 || p_response->success == 0 ) {
        //goto error;
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
        at_response_free( p_response );
        return;
    }

    memset( &response, 0, sizeof( response ) );
#endif
    /* FIXME fill in messageRef and ackPDU */
    RIL_onRequestComplete( t, RIL_E_SUCCESS, &response, sizeof( response ) );
    at_response_free( p_response );
    return;

}

void requestSMSAcknowledge_usegoogleoriginal( void* data, size_t datalen, RIL_Token t )
{
    /* modified by zte-yuyang begin  we always think the sms received correct */
    /*   int ackSuccess;
        int err;
        ackSuccess = ((int *)data)[0];
        if (ackSuccess == 1)
        {
            err = at_send_command("AT+CNMA=1", NULL);
        }
        else if (ackSuccess == 0)
        {
            err = at_send_command("AT+CNMA=2", NULL);
        }
        else
        {
            ARLOGD("unsupported arg to RIL_REQUEST_SMS_ACKNOWLEDGE\n");
            //goto error;

            RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
            return;
        }
        */
    /* modified by zte-yuyang end*/
    RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    /*
    error:
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    */
}


void requestWriteSmsToSim( void* data, size_t datalen, RIL_Token t )

{
    RIL_SMS_WriteArgs* p_args;
    char* cmd;
    int length;
    int err;
    ATResponse* p_response = NULL;
    p_args = ( RIL_SMS_WriteArgs* )data;
    length = strlen( p_args->pdu ) / 2;
    if ((ODM_CT_OPERATOR_3G == cur_oper) ||(ODM_CT_OPERATOR_4G == cur_oper)) {
        asprintf(&cmd,"AT^HCMGW=%d,%d",length,p_args->status);
        err = at_send_command_sms(cmd,p_args->pdu,"^HCMGW:",&p_response);
    } else {
        asprintf( &cmd, "AT+CMGW=%d,%d", length, p_args->status );

        err = at_send_command_sms( cmd, p_args->pdu, "+CMGW:", &p_response );
    }
    if ( err != 0 || p_response->success == 0 ) {
        //goto error;
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    } else {
        RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    }
    at_response_free( p_response );
    return;
}


void requestDeleteSmsOnSim( void* data, size_t datalen, RIL_Token t )

{
    char* cmd;
    ATResponse* p_response;
    int err;
    p_response = NULL;
    if(ODM_CT_OPERATOR_3G == cur_oper) {
        asprintf( &cmd, "AT$QCMGD=%d", ( ( int* )data )[0] );
        err = at_send_command( cmd, &p_response );
    } else {
        asprintf( &cmd, "AT+CMGD=%d", ( ( int* )data )[0] );
        err = at_send_command( cmd, &p_response );
    }
    free( cmd );
    if ( err < 0 || p_response->success == 0 ) {
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    } else {
        RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    }
    at_response_free( p_response );
}


// The follow functions are used to implement the  RIL_REQUEST_GSM_GET_BROADCAST_SMS_CONFIG request

int numbercaculatebycomma( char* pdata )
{
    int count = 0;

    while( *pdata ) {
        if( ( *pdata == ',' ) && ( *( pdata + 1 ) != '\0' ) ) {
            count++;
        }

        pdata++;
    }
    count++;
    return count;
}
int AIsspace(char c)
{
    if(c =='\t'|| c =='\n'|| c ==' ')
        return 1;
    else
        return 0;
}
/**
*the ZTE_nextTok is like nextTok in the at_tok.c
*it is for handling string
*
*/
static void ZTE_skipWhiteSpace( char** p_cur )
{
    if ( *p_cur == NULL ) {
        return;
    }

    while ( **p_cur != '\0' && AIsspace( **p_cur ) ) {
        ( *p_cur )++;
    }
}

static void ZTE_skipNextComma( char** p_cur )
{
    if ( *p_cur == NULL ) {
        return;
    }

    while ( **p_cur != '\0' &&** p_cur != ',' ) {
        ( *p_cur )++;
    }

    if ( **p_cur == ',' ) {
        ( *p_cur )++;
    }
}

static char* ZTE_nextTok( char** p_cur )
{
    char* ret = NULL;

    ZTE_skipWhiteSpace( p_cur );

    if ( *p_cur == NULL ) {
        ret = NULL;
    } else if ( **p_cur == '"' ) {
        ( *p_cur )++;
        ret = strsep( p_cur, "\"" );
        ZTE_skipNextComma( p_cur );
    } else {
        ret = strsep( p_cur, "," );
    }

    return ret;
}





void makeBSC( RIL_GSM_BroadcastSmsConfigInfo* BSC, int num, char* mids, char* dcss, int mids_num, int dcss_num, int select )
{
    int i;
    int from = 0;
    int to = 0;
    char* ret;
    char* end;
    char* str_from;

    for( i = 0; i < num; i++ ) {
        BSC[i].selected = select ^ 0x01;
    }

    i = 0;

    while( mids != NULL ) {
        if( *mids == '\0' ) {
            break;
        }

        ret = ZTE_nextTok( &mids );
        str_from = strsep( &ret, "-" );

        if( ret == NULL ) {
            BSC[i].fromServiceId = strtol( str_from, &end, 10 );
            BSC[i].toServiceId =  BSC[i].fromServiceId;
            i++;
        } else {
            BSC[i].fromServiceId = strtol( str_from, &end, 10 );
            BSC[i].toServiceId =  strtol( ret, &end, 10 );
            i++;
        }

    }

    i = 0;

    while( dcss != NULL ) {
        if( *dcss == '\0' ) {
            break;
        }

        ret = ZTE_nextTok( &dcss );
        str_from = strsep( &ret, "-" );

        if( ret == NULL ) {
            BSC[i].fromCodeScheme = strtol( str_from, &end, 10 );
            BSC[i].toCodeScheme =  BSC[i].fromCodeScheme;
            i++;
        } else {
            BSC[i].fromCodeScheme = strtol( str_from, &end, 10 );
            BSC[i].toCodeScheme =  strtol( ret, &end, 10 );
            i++;
        }

    }
}
void requestGsmGetBroadcastSMSConfig( void* data, size_t datalen, RIL_Token t )
{
    int err;
    char* line;
    int select;
    char* mids;
    int mids_num = 0;
    char* dcss;
    int dcss_num = 0;
    int num;
    int i;
    RIL_GSM_BroadcastSmsConfigInfo** response;
    RIL_GSM_BroadcastSmsConfigInfo* BSC;
    ATResponse* p_response;

    err = at_send_command_singleline( "AT+CSCB?", "+CSCB:", &p_response );

    if( err < 0 || p_response->success == 0 ) {
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    } else {
        line = p_response->p_intermediates->line;
        err = at_tok_start( &line );               // skip the +CSCB:

        if( err < 0 ) {
            at_response_free( p_response );
            RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
            return;
        }

        err = at_tok_nextint( &line, &select );

        if( err < 0 ) {
            at_response_free( p_response );
            RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
            return;
        }

        err = at_tok_nextstr( &line, &mids );

        if( err < 0 ) {
            at_response_free( p_response );
            RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
            return;
        }

        err = at_tok_nextstr( &line, &dcss );

        if( err < 0 ) {
            at_response_free( p_response );
            RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
            return;
        }

        mids_num = numbercaculatebycomma( mids );
        dcss_num = numbercaculatebycomma( dcss );
        num = ( mids_num > dcss_num ) ? mids_num : dcss_num;
        BSC = ( RIL_GSM_BroadcastSmsConfigInfo* )malloc( num * sizeof( RIL_GSM_BroadcastSmsConfigInfo ) );
        response = ( RIL_GSM_BroadcastSmsConfigInfo** )malloc( num * sizeof( RIL_GSM_BroadcastSmsConfigInfo* ) );
        memset( BSC, -1, num * sizeof( RIL_GSM_BroadcastSmsConfigInfo ) );

        for( i = 0; i < num; i++ ) {
            response[i] = &BSC[i];
        }

        makeBSC( BSC, num, mids, dcss, mids_num, dcss_num, select );

        RIL_onRequestComplete( t, RIL_E_SUCCESS, response, num * sizeof( RIL_GSM_BroadcastSmsConfigInfo* ) );
        free( BSC );
        free( response );
    }

    at_response_free( p_response );
}
// RIL_REQUEST_GSM_SET_BROADCAST_SMS_CONFIG request function
char* substrsep( char** srcstr, char* substr )
{
    char* ret = *srcstr;
    int loc = 0;

    if( strlen( *srcstr ) < strlen( substr ) ) {
        *srcstr = NULL;
        return ret;
    }

    if( strstr( *srcstr, substr ) == NULL ) {
        *srcstr = NULL;
        return ret;
    }

    *srcstr = strstr( *srcstr, substr );
    loc = strlen( ret ) - strlen( *srcstr );
    *srcstr = *srcstr + ( strlen( substr ) );

    *( ret + loc ) = '\0';

    return ret;
}
void removefromstr( char* substr, char* oldstr, char** newstr )
{
    char* ret;
    int len = 0;

    ret = substrsep( &oldstr, substr );
    asprintf( newstr, "%s", ret );

    while( oldstr != NULL ) { // find substr in oldstr
        if( *oldstr == ',' ) {
            oldstr++;
        }

        asprintf( newstr, "%s%s", *newstr, oldstr );
        ret = substrsep( &oldstr, substr );
    }
}
void addtostr( char* substr, char* oldstr, char** newstr )
{
    removefromstr( substr, oldstr, newstr );
    asprintf( newstr, "%s%s", *newstr, substr );
}
int createnewMIDSS( void* data, size_t datalen, char** oldmidsstr, char** newmidsstr )
{
    RIL_GSM_BroadcastSmsConfigInfo** gsmBciPtrs = ( RIL_GSM_BroadcastSmsConfigInfo** )data;
    int num = datalen / sizeof( RIL_GSM_BroadcastSmsConfigInfo* );
    char* sub_mid_str;
    int len;
    int i;

    for( i = 0; i < num; i++ ) { // for services ids
        if( ( gsmBciPtrs[i]->fromServiceId ) != ( gsmBciPtrs[i]->toServiceId ) ) {
            asprintf( &sub_mid_str, "%d-%d,", gsmBciPtrs[i]->fromServiceId, gsmBciPtrs[i]->toServiceId );
        } else {
            asprintf( &sub_mid_str, "%d,", gsmBciPtrs[i]->fromServiceId );
        }

        if( 1 == gsmBciPtrs[i]->selected ) {
            addtostr( sub_mid_str, *oldmidsstr, newmidsstr );
        } else if ( 0 == gsmBciPtrs[i]->selected ) {
            removefromstr( sub_mid_str, *oldmidsstr, newmidsstr );
        }

        *oldmidsstr = *newmidsstr;
    }

    if( **newmidsstr == '\0' ) {
        return -1;
    }

    len = strlen( *newmidsstr );

    if( *( *newmidsstr + len - 1 ) == ',' ) {
        *( *newmidsstr + len - 1 ) = '\0';
    }

    return 0;
}
void createnewDICSS( void* data, size_t datalen, char** olddcssstr, char** newdcssstr )
{
    RIL_GSM_BroadcastSmsConfigInfo** gsmBciPtrs = ( RIL_GSM_BroadcastSmsConfigInfo** )data;
    int num = datalen / sizeof( RIL_GSM_BroadcastSmsConfigInfo* );
    char* sub_dcs_str;
    int len;
    int i;

    for( i = 0; i < num; i++ ) { //for CodeScheme configration
        if( ( gsmBciPtrs[i]->fromCodeScheme ) != ( gsmBciPtrs[i]->toCodeScheme ) ) {
            asprintf( &sub_dcs_str, "%d-%d,", gsmBciPtrs[i]->fromCodeScheme, gsmBciPtrs[i]->toCodeScheme );
        } else {
            asprintf( &sub_dcs_str, "%d,", gsmBciPtrs[i]->fromCodeScheme );
        }

        if( 1 == gsmBciPtrs[i]->selected ) {
            addtostr( sub_dcs_str, *olddcssstr, newdcssstr );
        } else if ( 0 == gsmBciPtrs[i]->selected ) {
            removefromstr( sub_dcs_str, *olddcssstr, newdcssstr );
        }

        *olddcssstr = *newdcssstr;
    }

    len = strlen( *newdcssstr );

    if( *( *newdcssstr + len - 1 ) == ',' ) {
        *( *newdcssstr + len - 1 ) = '\0';
    }
}
void requestGsmSetBroadcastSMSConfig( void* data, size_t datalen, RIL_Token t )
{
    int err;
    char* cmd;
    char* line;
    ATResponse* p_response;
    int select = -1;
    char* oldmidsstr, *newmidsstr;
    char* olddcssstr, *newdcssstr;

    err = at_send_command_singleline( "AT+CSCB?", "+CSCB:", &p_response );
    line = p_response->p_intermediates->line;
    err = at_tok_start( &line );               // skip the +CSCB:
    err = at_tok_nextint( &line, &select );
    err = at_tok_nextstr( &line, &oldmidsstr );
    err = at_tok_nextstr( &line, &olddcssstr );

    if( *oldmidsstr != '\0' ) {
        asprintf( &oldmidsstr, "%s,", oldmidsstr );
    }

    if( *olddcssstr != '\0' ) {
        asprintf( &olddcssstr, "%s,", olddcssstr );
    }

    err = createnewMIDSS( data, datalen, &oldmidsstr, &newmidsstr );

    if( err == -1 ) {
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
        at_response_free( p_response );
        return;
    }

    createnewDICSS( data, datalen, &olddcssstr, &newdcssstr );
    asprintf( &cmd, "AT+CSCB=0,\"%s\",\"%s\"", newmidsstr, newdcssstr );

    at_response_free( p_response );
    err = at_send_command( "AT+CSCB=1", &p_response );

    if( err < 0 || p_response->success == 0 ) {
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
        at_response_free( p_response );
        return;
    }

    at_response_free( p_response );
    err = at_send_command( cmd, &p_response );

    if( err < 0 || p_response->success == 0 ) {
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    } else {
        RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    }

    at_response_free( p_response );
}
// RIL_REQUEST_GSM_SMS_BROADCAST_ACTIVATION
void requestGsmSMSBroadcastActivation( void* data, size_t datalen, RIL_Token t )
{
    int activate_flag = ( ( int* )data )[0];
    int err;
    char* cmd;
    ATResponse* p_response;
    if(ODM_CT_OPERATOR_3G == cur_oper) {
        if( 0 == activate_flag ) {
            asprintf( &cmd, "AT$QCNMI=,,2,," );
        } else if ( 1 == activate_flag ) {
            asprintf( &cmd, "AT$QCNMI=,,0,," );
        } else {
            RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
            return;
        }
    } else {
        if( 0 == activate_flag ) {
            asprintf( &cmd, "AT+CNMI=,,2,," );
        } else if ( 1 == activate_flag ) {
            asprintf( &cmd, "AT+CNMI=,,0,," );
        } else {
            RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
            return;
        }
    }

    err = at_send_command( cmd, &p_response );

    if( err < 0 || p_response->success == 0 ) {
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    } else {
        RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    }

    at_response_free( p_response );
}
void requestGetSMSCAddress( void* data, size_t datalen, RIL_Token t )
{
    int err;
    ATResponse* p_response = NULL;
    char* line;
    char response[22];

    err = at_send_command_singleline( "AT+CSCA?", "+CSCA:", &p_response );

    if( err < 0 || p_response->success == 0 ) {
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    } else {
        line = p_response->p_intermediates->line;
        err = at_tok_start( &line );               // skip the +CSCA:

        if( err < 0 ) {
            at_response_free( p_response );
            RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
            return;
        }

        err = at_tok_nextstr( &line, &response );  // get the sms center string

        if( err < 0 ) {
            at_response_free( p_response );
            RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
            return;
        }

        RIL_onRequestComplete( t, RIL_E_SUCCESS, &response, sizeof( response ) );
    }

    at_response_free( p_response );
}
void requestSetSMSCAddress( void* data, size_t datalen, RIL_Token t )
{
    char* center_num = ( char* )data;
    char* cmd;
    int err;
    ATResponse* p_response;

    if( center_num[0] == '+' ) {
        asprintf( &cmd, "AT+CSCA=%s,145", center_num );    // international number
    } else {
        asprintf( &cmd, "AT+CSCA=%s,161", center_num );
    }

    err = at_send_command( cmd, &p_response );

    if( err < 0 || p_response->success == 0 ) {
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    } else {
        RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    }

    at_response_free( p_response );
}


void requestReportSMSMemoryStatus( void* data, size_t datalen, RIL_Token t )
{
    int memory_availble = ( ( int* )data )[0];
    int err;
    //char* cmd;
    char cmd[512];
    ATResponse* p_response;
    if(ODM_CT_OPERATOR_3G == cur_oper) {
        if( 1 == memory_availble ) {
            sprintf( &cmd, "AT$QCNMI=3,1" );
        } else if ( 0 == memory_availble ) {
            sprintf( &cmd, "AT$QCNMI=0,0" );
        } else {
            RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
            return;
        }
    } else {
        if( 1 == memory_availble ) {
            sprintf( &cmd, "AT+CNMI=3,1" );
        } else if ( 0 == memory_availble ) {
            sprintf( &cmd, "AT+CNMI=0,0" );
        } else {
            RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
            return;
        }
    }

    err = at_send_command( cmd, &p_response );

    if( err < 0 || p_response->success == 0 ) {
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    } else {
        RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    }

    at_response_free( p_response );
}
/*  functions called when AT command comes up
 *
 */

#if 1

void onNewSmsNotification( char* s )
{
    //add by zte-tony
    /* can't issue AT commands here -- call on main thread */
    RLOGD( "********enter onNewSmsNotification********" );


    long location;
    char* response = NULL;
    char* tmp;
    char* cmd;
    char* line = NULL;
    int err;

    if( strStartsWith( s, "+CMTI:" ) ) {
        sms_type = SMS_GENERAL;
    } else if ( strStartsWith( s, "+CDSI:" ) ) {
        sms_type = SMS_SEND_REPORT;


    } else if( strStartsWith( s, "+CBMI:" ) ) {
        sms_type = SMS_BROADCAST;
    }

    line = strdup( s );
    tmp = line;
    at_tok_start( &tmp );

    err = at_tok_nextstr( &tmp, &response );

    if ( err < 0 ) {
        RLOGD( "sms request fail" );
        free( line );
        return;
    }

    /*  modified by zte-yuang for support new SMS at SIM begin */
    /*
    if (!strcmp(response, "SM"))
    {
        RLOGD("sms request arrive but it is not a new sms");
        free(line);
        return;
    }
    */
    /*  modified by zte-yuang for support new SMS at SIM end */

    /* Read the memory location of the sms */
    err = at_tok_nextint( &tmp, &location );

    if ( err < 0 ) {
        RLOGD( "error parse location" );
        free( line );
        return;
    }

    /*
    asprintf(&cmd, "AT+CPMS=%s,%s,%s", "ME","ME","ME");
    //at_send_command("AT+CPMS=\"ME\",\"ME\",\"ME\"", NULL);
    at_send_command(cmd, NULL);
    free(cmd);
            if (!strcmp(response, "SR"))
        {
            NEW_SMS_TYPE =
           //err=at_send_command("AT+CPMS=\"SR\",\"SR\",\"SR\"", NULL);
           asprintf(&cmd, "AT+CPMS=%s,%s,%s", "SR","SR","SR");
           err = at_send_command(cmd, NULL);
           free(cmd);
                if (err < 0)
    {
        RLOGD("******** set cpms failed,so we lost sms report ********");
         RLOGD("******** err=%d",err);
         return;
        }
    }


        */




    RLOGD( "********LEAVE onNewSmsNotification********" );

    RIL_requestTimedCallback(receiveSMS,(void*)location,NULL );



    free( line );
}

#endif

/*yufeilong modify for SLM770A read sms after wake up20230404 begin*/
void reportUnreadSMS()
{
    int err = -1;
    long location = -1;
    char *stat = NULL;
    ATResponse *p_response = NULL;
    ATLine *atLine = NULL;
    char *line = NULL;

    err = at_send_command_multiline("AT+CMGL=\"REC UNREAD\"", "+CMGL:", &p_response);
    if (err < 0 || p_response->success == 0) {
        goto error;
    }

    for (atLine = p_response->p_intermediates; atLine != NULL; atLine = atLine->p_next) {
        line = atLine->line;
        if (!strStartsWith(line, "+CMGL:")) {
            continue;
        }
        err = at_tok_start(&line);
        if (err < 0) {
            goto error;
        }
        err = at_tok_nextint(&line, &location);
        if ( err < 0 ) {
            RLOGD("error parse location");
            goto error;
        }
        RLOGD("report unread sms");
        RIL_requestTimedCallback(receiveSMS,(void*)location,NULL );
    }

error:
    at_response_free(p_response);
}
/*yufeilong modify for SLM770A read sms after wake up20230404 end*/
static void receiveSMS(void *param)
{
    /*[zhaopf@meigsmart.com-2020-0619]modify for Android6.0, Android5.0 support { */
    long location = (long)param;
    /*[zhaopf@meigsmart.com-2020-0619]modify for Android6.0, Android5.0 support } */
    int err = 0;
    char *cmd;
    asprintf(&cmd, "AT+CMGR=%d", location);
    /* request the sms in a specific location */
    err = at_send_command(cmd, NULL);
    free(cmd);
    // if (err < 0) return;

    /* remove the sms from specific location XXX temp fix*/
    asprintf(&cmd, "AT+CMGD=%d,0", location);
    at_send_command(cmd, NULL);
    free(cmd);
}
