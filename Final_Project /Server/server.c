#include "readnwrite.h"
#include "func.h"


int main(int argc, char* argv[])
{
    struct sockaddr_in serv_addr; 
    struct sockaddr_in clnt_addr; 
    socklen_t clnt_addr_size;

    APP_MSG ID;
    APP_MSG PW;
    APP_MSG MSG_IN;
    APP_MSG MSG_OUT;

    unsigned char session_key[AES_KEY_128] = {0x00, };
    unsigned char iv[AES_KEY_128] = {0x00, };
    unsigned char buffer[BUFSIZE] = {0x00, };
    unsigned char id_mac[MAC_SIZE] = {0x00, };
    unsigned char pw_mac[MAC_SIZE] = {0x000, };
    unsigned char rec_id_mac[MAC_SIZE] = {0x00, };
    unsigned char rec_pw_mac[MAC_SIZE] = {0x00, };

    char server_file[2*FILE_NAME_LEN] = "./server_file/";
    char recv_id[IDPW_SIZE] = {0x00, };
    char recv_pw[IDPW_SIZE] = {0x00, };
    char file_name[BUF_SIZE] = {0x00, };
    char *save_file_name = NULL;
    char the_file[FILE_NAME_LEN] = {0x00, };
    char the_other_file[FILE_NAME_LEN] = {0x00, };
    char buff[BUFSIZE];

    int cnt_i;
    int path_len = strlen(server_file);
    int serv_sock; 
    int clnt_sock;
    int current_type = NOTHING_SERVER_COMMAND;
    int type;
    int len;
    int ciphertext_len;
    int publickey_len;
    int encryptedkey_len;
    int fd = -1;
    int file_len = 0x00;

    BIO *bp_public = NULL, *bp_private = NULL;
    BIO *pub = NULL;
    RSA *rsa_pubkey = NULL, *rsa_privkey = NULL;

    pid_t pid;
    struct sigaction act;
    DIR *dir;
    struct dirent *ent;
    
    if (argc != 2)
    {
        fprintf(stderr, "%s <port>\n", argv[0]);
    }

    RAND_poll();
    for (int cnt_i = 0; cnt_i < AES_KEY_128; cnt_i++)
    {
        iv[cnt_i] = (unsigned char)cnt_i;
    }

    act.sa_handler = read_childproc;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    int state = sigaction(SIGCHLD, &act, 0);

    RSAES_generator();
    serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (serv_sock == -1)
    {
        error_handling("socket() error");
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;                
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(atoi(argv[1]));     

    if (bind(serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
    {
        error_handling("bind() error");
    }

    if (listen(serv_sock, 5) == -1)
    {
        error_handling("listen() error");
    }
    
    for (;;)
    {
        clnt_addr_size = sizeof(clnt_addr);
        clnt_sock = accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);
        if (clnt_sock == -1)
        {
            continue;
        }
        else
        {
            printf("[***NEW CLIENT CONNECTED***]\n");
        }

        bp_public = BIO_new_file("public.pem", "r");
        if (!PEM_read_bio_RSAPublicKey(bp_public, &rsa_pubkey, NULL, NULL))
        {
            goto ERROR;
        }
        //reading private key
        bp_private = BIO_new_file("private.pem", "r");
        if (!PEM_read_bio_RSAPrivateKey(bp_private, &rsa_privkey, NULL, NULL)) 
        {
            goto ERROR;
        }

        memset(&MSG_IN, 0, sizeof(APP_MSG));
        type = readn(clnt_sock, &MSG_IN, sizeof(APP_MSG));
        MSG_IN.type = ntohl(MSG_IN.type);
        MSG_IN.msg_len = ntohl(MSG_IN.msg_len); 
        if (type == -1)
        {
            error_handling("readn() error");
        }
        else if (type == 0)
        {
            error_handling("reading EOF");
        }

        if (MSG_IN.type != PUBLIC_KEY_REQUEST)
        {
            error_handling("message error 1");
        }
        else
        {
       
            memset(&MSG_OUT, 0, sizeof(APP_MSG));
            MSG_OUT.type = PUBLIC_KEY;
            MSG_OUT.type = htonl(MSG_OUT.type);

            pub = BIO_new(BIO_s_mem()); 
            PEM_write_bio_RSAPublicKey(pub, rsa_pubkey); 
            publickey_len = BIO_pending(pub); 

            BIO_read(pub, MSG_OUT.payload, publickey_len);
            MSG_OUT.msg_len = publickey_len;
            MSG_OUT.msg_len = htonl(MSG_OUT.msg_len);
            
            type = writen(clnt_sock, &MSG_OUT, sizeof(APP_MSG));
            if (type == -1)
            {
                error_handling("writen() error");
                break;
            }
        }

        memset(&MSG_IN, 0, sizeof(APP_MSG));
        type = readn(clnt_sock, &MSG_IN, sizeof(APP_MSG));
        MSG_IN.type = ntohl(MSG_IN.type);
        MSG_IN.msg_len = ntohl(MSG_IN.msg_len);
        if (MSG_IN.type != ENCRYPTED_KEY)
        {
            error_handling("message error 2");
        } 
        else
        {
            encryptedkey_len = RSA_private_decrypt(MSG_IN.msg_len, MSG_IN.payload, buffer, rsa_privkey, RSA_PKCS1_OAEP_PADDING); 
            memcpy(session_key, buffer, encryptedkey_len);
        }

        if (clnt_sock == -1)
        {
            continue;
        }
        else
        {
            printf("New client connected\n");
        }

        pid = fork();

        if (pid == 0) // child process
        {
            close(serv_sock);

            int n;
            while(current_type != LOGIN_SUCCESS)
            {
                if(current_type == ERROR)
                    break;
                n = readn(clnt_sock, &ID, sizeof(APP_MSG));
                n = readn(clnt_sock, &PW, sizeof(APP_MSG));

                ID.type = ntohl(ID.type);
                PW.type = ntohl(PW.type);

                ID.msg_len = ntohl(ID.msg_len);
                PW.msg_len = ntohl(PW.msg_len);

                if (ID.type == PW.type)
                    current_type = ID.type;
                else
                    current_type = TYPE_ERROR;
    
                readn(clnt_sock, rec_id_mac, sizeof(rec_id_mac));
                readn(clnt_sock, rec_pw_mac, sizeof(rec_pw_mac));

                int pt_id_len = decrypt(ID.payload, ID.msg_len, session_key, iv, (unsigned char *)recv_id);
                int pt_pw_len = decrypt(PW.payload, PW.msg_len, session_key, iv, (unsigned char *)recv_pw);
            
                HMAC_SHA256_Encrpyt(ID.payload,pt_id_len, session_key, strlen(session_key), id_mac);
                HMAC_SHA256_Encrpyt(PW.payload,pt_pw_len, session_key, strlen(session_key), pw_mac);


                if ((!strcmp(rec_id_mac, id_mac) ) || !strcmp(rec_pw_mac, pw_mac))
                {
                    printf("ERROR : MAC of ID or PW is not Correct\n");
                    current_type = ERROR;
                    continue;
                }
                
                int user_check = 0x00;
                switch (current_type)
                {
                    case CHECK_CLIENT:
                        user_check = check_client_in_server_data(recv_id, recv_pw);
                   
                        if (user_check == TRUE)
                        {
                            current_type = LOGIN_SUCCESS;
                            memset(&MSG_OUT, 0, sizeof(APP_MSG));
                            MSG_OUT.type = current_type;
                            MSG_OUT.type = htonl(MSG_OUT.type);
                            writen(clnt_sock, &MSG_OUT, sizeof(APP_MSG));
                        }
                        else if (user_check == FALSE)
                        {
                            printf("[XXX LOGIN FAIL! XXX]\n");
                            current_type = LOGIN_FAIL;
                        }
                        break;

                    case REGISTER_MSG:
                        register_client(recv_id, recv_pw);
                        printf("[***RESGISTER SUCESS!***]\n");
                        current_type = REGISTER_SUCCESS;
                        break;

                    case TYPE_ERROR:
                        printf("[XXX--TYPE ERROR--XXX]\n");
                        current_type = TYPE_ERROR;
                        break;

                    default:
                        break;
                }

                if (current_type != LOGIN_SUCCESS)
                {
                    memset(&MSG_OUT, 0, sizeof(APP_MSG));
                    MSG_OUT.type = current_type;
                    MSG_OUT.type = htonl(MSG_OUT.type);
                    writen(clnt_sock, &MSG_OUT, sizeof(APP_MSG));
                    current_type = NOTTHING_MSG_TYPE;
                }
            }

            printf("[***LOGIN SUCESS!***]\n");
            current_type = NOTHING_SERVER_COMMAND;
            while (current_type != QUIT)
            {
                memset(&MSG_IN, 0, sizeof(APP_MSG));
                memset(&MSG_OUT, 0, sizeof(APP_MSG));
                readn(clnt_sock, &MSG_IN, sizeof(APP_MSG));
                MSG_IN.type = ntohl(MSG_IN.type);
                current_type = MSG_IN.type;

                switch (current_type)
                {
                    case UP:
                        readn(clnt_sock, id_mac, sizeof(id_mac));
                        MSG_IN.msg_len = ntohl(MSG_IN.msg_len);
                        ciphertext_len = decrypt(MSG_IN.payload, MSG_IN.msg_len, session_key, iv, (unsigned char *)the_other_file);
                        HMAC_SHA256_Encrpyt(the_other_file,strlen(the_other_file),session_key,strlen(session_key),pw_mac);
                        if (!strcmp(id_mac, pw_mac))
                        {
                            printf("[XXX HASH ERROR XXX]\n");
                            break;
                        }
                        
                        save_file_name = (char*)calloc(ciphertext_len + path_len, 1 );
                        for(cnt_i = 0 ; cnt_i < path_len ; cnt_i ++)
                        {
                            save_file_name[cnt_i] = server_file[cnt_i];
                        }

                        for(cnt_i = path_len ; cnt_i < path_len + ciphertext_len ; cnt_i ++)
                        {
                            save_file_name[cnt_i] = the_other_file[cnt_i - path_len];
                        }
                            
                        fd = open(save_file_name, O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU);
                        if (fd == -1)
                        {
                            error_handling("open() error");
                        }

                        for (;;)
                        {
                            memset(&MSG_IN, 0, sizeof(APP_MSG));
                            readn(clnt_sock, &MSG_IN, sizeof(APP_MSG));
                            MSG_IN.msg_len = ntohl(MSG_IN.msg_len);
                            MSG_IN.type = ntohl(MSG_IN.type);
                            if (MSG_IN.type == EOF | MSG_IN.type == 0)
                            {
                                break;
                            }
                            if (MSG_IN.type == FILE_DATA)
                            {
                                readn(clnt_sock, id_mac, sizeof(id_mac));
                                file_len = decrypt(MSG_IN.payload, MSG_IN.msg_len, session_key, iv, (unsigned char*)buff);
                                HMAC_SHA256_Encrpyt(buff,strlen(buff),session_key,strlen(session_key),pw_mac);
                                if (!strcmp(id_mac, pw_mac))
                                {
                                    printf("[XXX HASH ERROR XXX]\n");
                                    break;
                                }
                                writen(fd, buff, file_len);
                            }
                            else if (MSG_IN.type == SEND_FINISH)
                            {
                                free(save_file_name);
                                close(fd);
                                printf("[***Upload Success***]\n");
                                current_type = NOTHING_SERVER_COMMAND;
                                break;
                            }
                        
                        }       
                        break;

                    case DOWN:

                        memset(the_file, 0, sizeof(the_file));
                        memset(id_mac, 0, sizeof(id_mac));
                        readn(clnt_sock, id_mac, sizeof(id_mac));
                        MSG_IN.msg_len = ntohl(MSG_IN.msg_len);
                        ciphertext_len = decrypt(MSG_IN.payload, MSG_IN.msg_len, session_key, iv, (unsigned char *)the_file);
                        
                        HMAC_SHA256_Encrpyt(the_file,strlen(the_file),session_key,strlen(session_key),pw_mac);
                        if (!strcmp(id_mac, pw_mac))
                        {
                            printf("[XXX HASH ERROR XXX]\n");
                            break;
                        }

                        save_file_name = (char*)calloc(ciphertext_len + path_len, 1 );
                        for(cnt_i = 0 ; cnt_i < path_len ; cnt_i ++)
                        {
                            save_file_name[cnt_i] = server_file[cnt_i];
                        }

                        for(cnt_i = path_len ; cnt_i < path_len + ciphertext_len ; cnt_i ++)
                        {
                            save_file_name[cnt_i] = the_file[cnt_i - path_len];
                        }
                      
                        fd =  open(save_file_name, O_RDONLY, S_IRWXU);
                        if (fd == -1)
                        {
                            error_handling("open() error");
                            memset(&MSG_OUT, 0, sizeof(APP_MSG));
                            MSG_OUT.type = htonl(NONE_FILE);
                            writen(clnt_sock, &MSG_OUT, sizeof(APP_MSG));
                        }
                        else
                        {
                            memset(&MSG_OUT, 0, sizeof(APP_MSG));
                            MSG_OUT.type = htonl(EXIST_FILE);
                            writen(clnt_sock, &MSG_OUT, sizeof(APP_MSG));
                        }
 
                        // File SENDING
                        for (;;)
                        {
                            memset(buff, 0x00, BUFSIZE);
                            memset(id_mac, 0, sizeof(id_mac));
                            memset(&MSG_OUT, 0, sizeof(APP_MSG));
                            file_len = readn(fd, buff, BUFSIZE);
                            if (file_len == 0)
                            {
                                printf("[*** FINISH FILE***]]\n");
                                break;
                            }
                            HMAC_SHA256_Encrpyt(buff,BUFSIZE,session_key,strlen(session_key),id_mac);
                            file_len = encrypt((unsigned char *)buff, file_len, session_key, iv, MSG_OUT.payload);
                            MSG_OUT.msg_len = htonl(file_len);
                            MSG_OUT.type = htonl(FILE_DATA);
                            writen(clnt_sock, &MSG_OUT, sizeof(APP_MSG));
                            writen(clnt_sock, id_mac, sizeof(id_mac));
                        }

                        memset(&MSG_OUT, 0, sizeof(APP_MSG));
                        MSG_OUT.type = htonl(SEND_FINISH);
                        writen(clnt_sock, &MSG_OUT, sizeof(APP_MSG));
                        
                        free(save_file_name);
                        close(fd);
                        current_type = NOTHING_SERVER_COMMAND;
                        break;

                    case LIST:

                        dir = opendir("./server_file/");
                        if (dir != NULL)
                        {
                            while ((ent = readdir(dir)) != NULL)
                            {
                                memset(file_name, 0, sizeof(file_name));
                                memcpy(file_name, ent->d_name, strlen(ent->d_name));

                                memset(id_mac, 0, sizeof(id_mac));
                                HMAC_SHA256_Encrpyt(file_name,strlen(file_name),session_key,strlen(session_key),id_mac);
                                len = encrypt((unsigned char*)file_name, strlen(file_name), session_key, iv, MSG_OUT.payload);
                                MSG_OUT.type = SEND_LIST;
                                MSG_OUT.msg_len = len;
                                MSG_OUT.type = htonl(MSG_OUT.type);
                                MSG_OUT.msg_len = htonl(MSG_OUT.msg_len);
                                writen(clnt_sock, &MSG_OUT, sizeof(APP_MSG));
                                writen(clnt_sock, id_mac, sizeof(id_mac));
                            }
                            current_type = SEND_FINISH;
                            MSG_OUT.type = SEND_FINISH;
                            MSG_OUT.type = htonl(MSG_OUT.type);
                            writen(clnt_sock, &MSG_OUT, sizeof(APP_MSG));
                            closedir(dir);
                        }
                        else
                        {
                            printf("[XXX- LIST-ERROR-XXX]\n");
                            return EXIT_FAILURE;
                        }

                        printf("[***FINISH --> WAIT***]\n");

                        current_type = NOTHING_SERVER_COMMAND;
                        break;
                    
                    case QUIT:
                        current_type = QUIT;
                        break;
                    default:
                        break;
                }
            }

            close(clnt_sock); 
            puts("[***CLIENT DISCONNECT***]");
        }
        else // parent process
        {
            close(clnt_sock); 
        }

    }
    close(serv_sock);

    ERROR:
        close(serv_sock);

    return 0;
}

static int _pad_unknopwn(void)
{
    unsigned long l;

    while ((l = ERR_get_error()) != 0)
    {
        if (ERR_GET_REASON(l) == RSA_R_UNKNOWN_PADDING_TYPE)
            return (1);    
    }
    return (0);
}
void error_handling(char *msg)
{
    fputs(msg, stderr);
    fputc('\n', stderr);
    exit(1);
}

int RSAES_generator()
{
    RSA *rsa; 
    BIO *bp_public = NULL, *bp_private = NULL; 
    unsigned long e_value = RSA_F4; 
    BIGNUM *exponent_e = BN_new();

    rsa = RSA_new();

    BN_set_word(exponent_e, e_value); 

    if (RSA_generate_key_ex(rsa, 2048, exponent_e, NULL) == '\0') 
    {
        fprintf(stderr, "RSA_generate_key_ex() error\n");
    }

    bp_public = BIO_new_file("public.pem", "w+");
    int ret = PEM_write_bio_RSAPublicKey(bp_public, rsa);

    if (ret != 1)
    {
        goto ERROR;
    }

    bp_private = BIO_new_file("private.pem", "w+");
    ret = PEM_write_bio_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL); 

    if (ret != 1)
    {
        goto ERROR;
    }

    ERROR:
        RSA_free(rsa);
        BIO_free_all(bp_public);
        BIO_free_all(bp_private);

    return ret;
}

int check_client_in_server_data(char *id, char *pw)
{
    FILE *fp = fopen("server_list_of_client.txt", "r");
    char buff[IDPW_SIZE] = {0,};
    char *id_buff = NULL,  *pw_buff = NULL, *temp = NULL;
    int check = 0;

    for (;;)
    {
        memset(buff, 0, IDPW_SIZE);
        fgets(buff, sizeof(buff), fp);
        if (buff[0] == 0)
        {
            check = 0;
            break;
        }
        id_buff = strtok(buff, " , ");
        temp = strtok(NULL, " , ");
        pw_buff = strtok(temp, "\n");
        
        if ((strcmp(id, id_buff) == 0) && (strcmp(pw, pw_buff) == 0))
        {
            check = TRUE;
            break;
        }
        else
        {
            check = FALSE;
        }
    }

    return check;
}

void register_client(char *client_id, char *client_pw)
{
    FILE *fp = fopen("server_list_of_client.txt", "a+");
    fprintf(fp, "%s", client_id);
    fprintf(fp, " , ");
    fprintf(fp, "%s", client_pw);
    fprintf(fp, "\n");
    fclose(fp);
}

void read_childproc(int sign) 
{
    pid_t PID;
    int status;
    PID = waitpid(-1, &status, WNOHANG); 
    printf("[***REMOVED PROCESS ID : %d***]\n", PID);
}
