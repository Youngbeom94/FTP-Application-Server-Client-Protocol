#include "readnwrite.h"
#include "func.h"

int main(int argc, char* argv[])
{
    int sock; 
    struct sockaddr_in serv_addr;

    APP_MSG ID;
    APP_MSG PW;
    APP_MSG MSG_IN;
    APP_MSG MSG_OUT;
    
    int fd = -1;
    int cnt_i = 0x00;
    int file_len = 0x00;
    int type;
    int plaintext_len;
    int ciphertext_len;
    int current_command = CLIENT_ID_PW;
    
    unsigned char session_key[AES_KEY_128] = {0x000, };
    unsigned char iv[AES_KEY_128] = {0x00, };
    unsigned char id_mac[MAC_SIZE] = {0x00,};
    unsigned char pw_mac[MAC_SIZE] = {0x00,};
    unsigned char net_work_mac[MAC_SIZE] = {0x00,};
    unsigned char testing_mac[MAC_SIZE] = {0x00,};

    char client_id[IDPW_SIZE] = {0x00, };
    char client_pw[IDPW_SIZE] = {0x00, }; 
    char file_name[BUF_SIZE] = {0x00, };
    char command[COMMEND_LEN];
    char upload_file_name[FILE_NAME_LEN] = {0, };
    char enc_file_name1[FILE_NAME_LEN] = {0, };
    char save_file_name[FILE_NAME_LEN] = {0, };
    char enc_file_name2[FILE_NAME_LEN] = {0, };
    char buff[BUFSIZE];

    BIO *rpub = NULL;
    RSA *rsa_pubkey = NULL;

    if (argc != 3)
    {
        printf("Usage: %s <IP><port>\n", argv[0]);
        exit(1);
    }

    RAND_poll();
    RAND_bytes(session_key, sizeof(session_key)); 

    for (int cnt_i = 0; cnt_i < AES_KEY_128; cnt_i++)
    {
        iv[cnt_i] = (unsigned char)cnt_i;
    }

    sock = socket(PF_INET, SOCK_STREAM, 0);

    if (sock == -1)
    {
        error_handling("socket() error");
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
    serv_addr.sin_port = htons(atoi(argv[2]));

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
    {
        error_handling("connect() error");
    }
    else
    {
        printf("[***COALA***] Server Connected.....................................\n");
    }

    memset(&MSG_OUT, 0, sizeof(MSG_OUT)); 
    MSG_OUT.type = PUBLIC_KEY_REQUEST; 
    MSG_OUT.type = htonl(MSG_OUT.type);

    type = writen(sock, &MSG_OUT, sizeof(APP_MSG)); 
    if (type == -1)
    {
        error_handling("writen() error");
    }

    memset(&MSG_IN, 0, sizeof(APP_MSG)); 
    type = readn(sock, &MSG_IN, sizeof(APP_MSG)); 
    MSG_IN.type = ntohl(MSG_IN.type);
    MSG_IN.msg_len = ntohl(MSG_IN.msg_len); 
    printf("\n");

    if (type == -1)
    {
        error_handling("readn() error");
    }
    else if (type == 0)
    {
        error_handling("reading EOF");
    }

    if (MSG_IN.type != PUBLIC_KEY)
    {
        error_handling("message error");
    }
    else
    {
      
        rpub = BIO_new_mem_buf(MSG_IN.payload, -1); 
        BIO_write(rpub, MSG_IN.payload, MSG_IN.msg_len);
        if (!PEM_read_bio_RSAPublicKey(rpub, &rsa_pubkey, NULL, NULL))
        {
            error_handling("PEM_read_bio_RSAPublicKey() error");
        }
    }

    memset(&MSG_OUT, 0, sizeof(APP_MSG));
    MSG_OUT.type = ENCRYPTED_KEY;
    MSG_OUT.type = htonl(MSG_OUT.type);
    MSG_OUT.msg_len = RSA_public_encrypt(sizeof(session_key), session_key, MSG_OUT.payload, rsa_pubkey, RSA_PKCS1_OAEP_PADDING);
    MSG_OUT.msg_len = htonl(MSG_OUT.msg_len);

    type = writen(sock, &MSG_OUT, sizeof(APP_MSG));

    if (type == -1)
    {
        error_handling("writen() error");
    }

    //Login process
    int user_input = 0;
    //While Start
    while(current_command != LOGIN_SUCCESS)
    {  
        switch (current_command)
        {
            case CLIENT_ID_PW:

                current_command = CHECK_CLIENT;
                printf("[***WELCOME TO COALA Server***]\n");
                memset(&ID, 0, sizeof(ID));
                memset(&PW, 0, sizeof(PW));

                printf("Client ID : ");
                if (fgets(client_id, IDPW_SIZE + 1, stdin) == NULL)
                    break;
                printf("Client PW : ");
                if (fgets(client_pw, IDPW_SIZE + 1, stdin) == NULL)
                    break;

                int id_len = strlen(client_id);
                if (client_id[id_len - 1] == '\n')
                    client_id[id_len - 1] = '\0';
                if (strlen(client_id) == 0)
                    break;

                int pw_len = strlen(client_pw);
                if (client_pw[pw_len - 1] == '\n')
                    client_pw[pw_len - 1] = '\0';
                if (strlen(client_pw) == 0)
                    break;


                HMAC_SHA256_Encrpyt(client_id,strlen(client_id), session_key, strlen(session_key), id_mac);
                id_len = encrypt((unsigned char *)client_id, id_len, session_key, iv, ID.payload);
                ID.type = current_command;
                ID.type = htonl(ID.type);
                ID.msg_len = htonl(id_len);
            
                HMAC_SHA256_Encrpyt(client_pw,strlen(client_pw), session_key, strlen(session_key), pw_mac);
                pw_len = encrypt((unsigned char *)client_pw, pw_len, session_key, iv, PW.payload);
                PW.type = current_command;
                PW.type = htonl(PW.type);
                PW.msg_len = htonl(pw_len);


                writen(sock, &ID, sizeof(APP_MSG));
                writen(sock, &PW, sizeof(APP_MSG));
                writen(sock, id_mac, sizeof(id_mac));
                writen(sock, pw_mac, sizeof(pw_mac));
                break;

            case LOGIN_FAIL:
                printf("[1] : Don't have an account? SIGN UP  [2] : SIGN IN Again\n");
                scanf("%d", &user_input);
                if (user_input == SIGN_UP)
                {
                    current_command = REGISTER_MSG;
                    printf("Enter ID/PW to register\n");
                    getchar();
                    memset(&ID, 0, sizeof(ID));
                    memset(&PW, 0, sizeof(PW));

                    // Input ID/PW
                    printf("ID : ");
                    if (fgets(client_id, IDPW_SIZE + 1, stdin) == NULL)
                        break;
                    printf("PW : ");
                    if (fgets(client_pw, IDPW_SIZE + 1, stdin) == NULL)
                        break;

                    int id_len = strlen(client_id);
                    if (client_id[id_len - 1] == '\n')
                        client_id[id_len - 1] = '\0';
                    if (strlen(client_id) == 0)
                        break;

                    int pw_len = strlen(client_pw);
                    if (client_pw[pw_len - 1] == '\n')
                        client_pw[pw_len - 1] = '\0';
                    if (strlen(client_pw) == 0)
                        break;

                    HMAC_SHA256_Encrpyt(client_id,strlen(client_id), session_key, strlen(session_key), id_mac);
                    id_len = encrypt((unsigned char *)client_id, id_len, session_key, iv, ID.payload);
                    ID.type = current_command;
                    ID.type = htonl(ID.type);
                    ID.msg_len = htonl(id_len);
            
                    HMAC_SHA256_Encrpyt(client_pw,strlen(client_pw), session_key, strlen(session_key), pw_mac);
                    pw_len = encrypt((unsigned char *)client_pw, pw_len, session_key, iv, PW.payload);
                    PW.type = current_command;
                    PW.type = htonl(PW.type);
                    PW.msg_len = htonl(pw_len);

                    writen(sock, &ID, sizeof(APP_MSG));
                    writen(sock, &PW, sizeof(APP_MSG));
                    writen(sock, id_mac, sizeof(id_mac));
                    writen(sock, pw_mac, sizeof(pw_mac));

                    printf("[***RESGISTER SUCESS!***]\n\n");
                    current_command = CLIENT_ID_PW;
                    break;
                }
                else if (user_input == SIGN_IN)
                {
                    getchar();
                    current_command = CLIENT_ID_PW;
                    break;
                }
                else
                {
                    printf("Input Error\n");
                    current_command = LOGIN_FAIL;
                    break;
                }

            default:
            break;
        }

        if (current_command != LOGIN_SUCCESS && current_command != CLIENT_ID_PW)
        {
            memset(&MSG_IN, 0, sizeof(APP_MSG));
            readn(sock, &MSG_IN, sizeof(APP_MSG));
            MSG_IN.type = ntohl(MSG_IN.type);
            current_command = MSG_IN.type;
        }
    }
    // While_End


    // Login Section
    printf("\n\n[***LOGIN SUCESS!***]\n");
    current_command = NOTHING_SERVER_COMMAND;
    // While_Start
    while(current_command != QUIT)
    {
        printf("Whay Can I do For You\n");
        printf("[1] : UP    [2] : DOWN     3 : LIST     4 : QUIT \n");
        scanf("%s", command);
        command[strlen(command)] = '\0';
    
        if (strcmp(command, "up") == 0 || strcmp(command, "UP") == 0)
            current_command = UP;
        else if (strcmp(command, "down") == 0 || strcmp(command, "DOWN") == 0)
            current_command = DOWN;
        else if (strcmp(command, "list") == 0 || strcmp(command, "LIST") == 0)
            current_command = LIST;
        else if (strcmp(command, "quit") == 0|| strcmp(command, "QUIT") == 0)
            current_command = QUIT;
        else
            current_command = NOTHING_SERVER_COMMAND;

        switch (current_command)
        {
            case NOTHING_SERVER_COMMAND:
                printf("Please Correct Command~!\n");
                break;

            case UP: 
                printf("Please Enter File Name for Upload : ");
                scanf("%s", upload_file_name);
                printf("Please Enter File Name For Save: ");
                scanf("%s", save_file_name);

                upload_file_name[strlen(upload_file_name)] = '\0';
                save_file_name[strlen(save_file_name)] = '\0';

                fd = open(upload_file_name, O_RDONLY, S_IRWXU);
                if (fd == -1)
                    error_handling("open() error");

                // Sending File Name
                memset(&MSG_OUT, 0, sizeof(APP_MSG));
                memcpy(enc_file_name2, save_file_name, strlen(save_file_name));

                HMAC_SHA256_Encrpyt(enc_file_name2, strlen(enc_file_name2), session_key, strlen(session_key), net_work_mac);
                plaintext_len = encrypt((unsigned char*)enc_file_name2, strlen(enc_file_name2), session_key, iv, MSG_OUT.payload);
                MSG_OUT.type = htonl(UP);
                MSG_OUT.msg_len = htonl(plaintext_len);
                writen(sock, &MSG_OUT, sizeof(APP_MSG));
                writen(sock, net_work_mac, sizeof(net_work_mac));

                // Sending File 
                for (;;)
                {
                    memset(buff, 0x00, BUFSIZE);
                    memset(net_work_mac, 0, sizeof(net_work_mac));
                    file_len = readn(fd, buff, BUFSIZE);
                    if (file_len == 0)
                    {
                        printf("[***FINISH FILE***]\n");
                        break;
                    }
                    HMAC_SHA256_Encrpyt(buff, file_len, session_key, strlen(session_key), net_work_mac);
                    file_len = encrypt((unsigned char*)buff, file_len, session_key, iv, MSG_OUT.payload);
                    MSG_OUT.msg_len = htonl(file_len);
                    MSG_OUT.type = htonl(FILE_DATA);
                    writen(sock, &MSG_OUT, sizeof(APP_MSG));
                    writen(sock, net_work_mac, sizeof(net_work_mac));
                }

                memset(&MSG_OUT, 0, sizeof(APP_MSG));
                MSG_OUT.type = htonl(SEND_FINISH);
                writen(sock, &MSG_OUT, sizeof(APP_MSG));
                close(fd);

                printf("[***UPLOAD SUCCESS***]\n");
                current_command = NOTHING_SERVER_COMMAND;
                break;

            case DOWN: 
                printf("[***DOWNLOAD FILE NAME***] : ");
                scanf("%s", upload_file_name);
                printf("[***Saved FILE NAME***] : ");
                scanf("%s", save_file_name);
                upload_file_name[strlen(upload_file_name)] = '\0';
                save_file_name[strlen(save_file_name)] = '\0';     
                fd = open(save_file_name, O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU);
    
                // Send File Name
                memset(&MSG_OUT, 0, sizeof(APP_MSG));
                memset(net_work_mac, 0, sizeof(net_work_mac));
                memcpy(enc_file_name1, upload_file_name, strlen(upload_file_name));

                HMAC_SHA256_Encrpyt(enc_file_name1,strlen(enc_file_name1), session_key, strlen(session_key), net_work_mac);
                plaintext_len = encrypt((unsigned char*)enc_file_name1, strlen(enc_file_name1), session_key, iv, MSG_OUT.payload);
                MSG_OUT.type = htonl(DOWN);
                MSG_OUT.msg_len = htonl(plaintext_len);
                writen(sock, &MSG_OUT, sizeof(APP_MSG));
                writen(sock, net_work_mac, sizeof(net_work_mac));

                 // Check File Exist
                memset(&MSG_IN, 0, sizeof(APP_MSG));
                readn(sock, &MSG_IN, sizeof(APP_MSG));
                MSG_IN.type = ntohl(MSG_IN.type);
                if (MSG_IN.type == NONE_FILE)
                {
                    printf("[XXX NO EXIST FILE XXX]\n");
                    current_command = DOWN;
                    break;
                }
                else if (MSG_IN.type == EXIST_FILE)
                {
                    printf("[***EXIST FILE***]\n");
                }

                // File Download
                for (;;)
                {
                    memset(&MSG_IN, 0, sizeof(APP_MSG));
                    memset(buff, 0, sizeof(buff));
                    memset(net_work_mac, 0, sizeof(net_work_mac));
                    memset(testing_mac, 0, sizeof(testing_mac));
                    readn(sock, &MSG_IN, sizeof(APP_MSG));
                    MSG_IN.msg_len = ntohl(MSG_IN.msg_len);
                    MSG_IN.type = ntohl(MSG_IN.type);
                    if (MSG_IN.type == EOF | MSG_IN.type == 0)
                    {
                        break;
                    }
                    if (MSG_IN.type == FILE_DATA)
                    {
                        readn(sock, net_work_mac, sizeof(net_work_mac));
                        file_len = decrypt(MSG_IN.payload, MSG_IN.msg_len, session_key, iv, (unsigned char *)buff);
                        HMAC_SHA256_Encrpyt(buff,strlen(buff), session_key, strlen(session_key), testing_mac);
                        if (!strcmp(net_work_mac, testing_mac))
                        {
                            printf("[XXX HASH ERROR XXX]\n");
                            break;
                        }
                        writen(fd, buff, file_len);
                    }
                else if (MSG_IN.type == SEND_FINISH)
                {
                    current_command = NOTHING_SERVER_COMMAND;
                    break;
                }
            }
            printf("[***DOWNLOAD FINISH***]\n");
            close(fd);
            break;


            case LIST: 
                memset(&MSG_OUT, 0, sizeof(APP_MSG));
                MSG_OUT.type = current_command;
                MSG_OUT.type = htonl(MSG_OUT.type);
                writen(sock, &MSG_OUT, sizeof(APP_MSG));
                current_command = NOTHING_SERVER_COMMAND;
                for (;;)
                {
                    memset(file_name,0,sizeof(file_name));
                    memset(&MSG_IN, 0, sizeof(APP_MSG));
                    memset(net_work_mac, 0, sizeof(net_work_mac));
                    memset(testing_mac, 0, sizeof(testing_mac));
                    readn(sock, &MSG_IN, sizeof(APP_MSG));


                    MSG_IN.type = ntohl(MSG_IN.type);
                    MSG_IN.msg_len = ntohl(MSG_IN.msg_len);
                    if (MSG_IN.type != SEND_FINISH)
                    {
                        readn(sock, net_work_mac, sizeof(net_work_mac));

                        ciphertext_len = decrypt(MSG_IN.payload, MSG_IN.msg_len, session_key, iv, (unsigned char*)file_name);
                        HMAC_SHA256_Encrpyt(file_name, ciphertext_len, session_key, strlen(session_key), testing_mac);
                        int hash_flag = TRUE;
                        for(int cnt_i = 0  ; cnt_i < MAC_SIZE  ; cnt_i ++)
                        {
                            if(testing_mac[cnt_i] != net_work_mac[cnt_i])
                            {
                                hash_flag = FALSE;
                                break;
                            }
                        }
                        if(hash_flag == FALSE)
                        {
                            printf("[XXX HASH ERROR XXX]\n");
                            current_command = NOTHING_SERVER_COMMAND;
                            break;
                        }
                        if(file_name[0] != '.')
                        {
                            printf("FILE NAME : %s\n", file_name);
                        }
                    }
                    else if (MSG_IN.type == SEND_FINISH)
                    {
                        current_command = NOTHING_SERVER_COMMAND;
                        break;
                    }
                }

                printf("[*** END LIST ***]\n\n\n");
                current_command = NOTHING_SERVER_COMMAND;
                break;

            case QUIT:
                current_command = QUIT;
                memset(&MSG_OUT, 0, sizeof(APP_MSG));
                MSG_OUT.type = current_command;
                MSG_OUT.type = htonl(MSG_OUT.type);
                writen(sock, &MSG_OUT, sizeof(APP_MSG));
                break;

            default:
                break;
        }
    }

    printf("QUIT\n");
    printf("BYE_Please Revisit COALA Server!~\n");
    close(sock);
    return 0;
}

void error_handling(char *msg)
{
    fputs(msg, stderr);
    fputc('\n', stderr);
    exit(1);
}