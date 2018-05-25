#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#pragma pack(1)

void hexdump(void *pAddressIn, long  lSize)
{
	char szBuf[100];
	long lIndent = 1;
	long lOutLen, lIndex, lIndex2, lOutLen2;
	long lRelPos;
	struct { char *pData; unsigned long lSize; } buf;
	unsigned char *pTmp, ucTmp;
	unsigned char *pAddress = (unsigned char *)pAddressIn;

	buf.pData = (char *)pAddress;
	buf.lSize = lSize;

	while (buf.lSize > 0)
	{
		pTmp = (unsigned char *)buf.pData;
		lOutLen = (int)buf.lSize;
		if (lOutLen > 16)
			lOutLen = 16;

		sprintf(szBuf, " >                            "
			"                      "
			"    %08lX", pTmp - pAddress);
		lOutLen2 = lOutLen;

		for (lIndex = 1 + lIndent, lIndex2 = 53 - 15 + lIndent, lRelPos = 0;
			lOutLen2;
			lOutLen2--, lIndex += 2, lIndex2++
			)
		{
			ucTmp = *pTmp++;

			sprintf(szBuf + lIndex, "%02X ", (unsigned short)ucTmp);
			if (!isprint(ucTmp))  ucTmp = '.';
			szBuf[lIndex2] = ucTmp;

			if (!(++lRelPos & 3))
			{
				lIndex++; szBuf[lIndex + 2] = ' ';
			}
		}

		if (!(lRelPos & 3)) lIndex--;

		szBuf[lIndex] = '<';
		szBuf[lIndex + 1] = ' ';

		printf("%s\n", szBuf);

		buf.pData += lOutLen;
		buf.lSize -= lOutLen;
	}
}


HINSTANCE hLThis = 0;
HINSTANCE hL = 0;
FILE *logfile = fopen("logfile", "a+");
FARPROC p[401] = { 0 };

struct a1
{
	UINT8 gap0[8];
	DWORD dword8;
	UINT8 gapC[12];
	DWORD dword18;
	UINT8 gap1C[4];
	DWORD dword20;
	UINT8 gap24[12];
	UINT8 byte30;
};

a1* data;

void OpenConsole()
{
	AllocConsole();
	freopen("conin$", "r", stdin);
	freopen("conout$", "w", stdout);
	freopen("conout$", "w", stderr);
	HWND consoleHandle = GetConsoleWindow();
	MoveWindow(consoleHandle, 1, 1, 680, 480, 1);
	printf("Console initialized.\n");
}

extern "C" BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		hL = LoadLibrary(_T(".\\libssl-1_1_org.dll"));
		if (!hL) return false;
		p[0] = GetProcAddress(hL, "SSL_use_PrivateKey");
		p[1] = GetProcAddress(hL, "SSL_load_client_CA_file");
		p[2] = GetProcAddress(hL, "SSL_dane_tlsa_add");
		p[3] = GetProcAddress(hL, "SSL_get_privatekey");
		p[4] = GetProcAddress(hL, "SSL_CTX_clear_options");
		p[5] = GetProcAddress(hL, "SSL_use_RSAPrivateKey_file");
		p[6] = GetProcAddress(hL, "DTLSv1_2_client_method");
		p[7] = GetProcAddress(hL, "SSL_CTX_get0_privatekey");
		p[8] = GetProcAddress(hL, "SSL_CIPHER_get_kx_nid");
		p[9] = GetProcAddress(hL, "SSL_CTX_use_serverinfo_file");
		p[10] = GetProcAddress(hL, "SSL_get_ex_data_X509_STORE_CTX_idx");
		p[11] = GetProcAddress(hL, "SSL_dane_clear_flags");
		p[12] = GetProcAddress(hL, "TLSv1_2_server_method");
		p[13] = GetProcAddress(hL, "SSL_get_state");
		p[14] = GetProcAddress(hL, "SSL_get_server_random");
		p[15] = GetProcAddress(hL, "SSL_CTX_set_default_passwd_cb");
		p[16] = GetProcAddress(hL, "SSL_CTX_set_purpose");
		p[17] = GetProcAddress(hL, "SSL_certs_clear");
		p[18] = GetProcAddress(hL, "SSL_set_connect_state");
		p[19] = GetProcAddress(hL, "SSL_CTX_use_RSAPrivateKey");
		p[20] = GetProcAddress(hL, "SSL_get_error");
		p[21] = GetProcAddress(hL, "SSL_set_tlsext_use_srtp");
		p[22] = GetProcAddress(hL, "SSL_get_client_CA_list");
		p[23] = GetProcAddress(hL, "SSL_CTX_set_options");
		p[24] = GetProcAddress(hL, "SSL_CTX_set_not_resumable_session_callback");
		p[25] = GetProcAddress(hL, "SSL_set_accept_state");
		p[26] = GetProcAddress(hL, "SSL_get0_dane_tlsa");
		p[27] = GetProcAddress(hL, "SSL_get_changed_async_fds");
		p[28] = GetProcAddress(hL, "SSL_set_hostflags");
		p[29] = GetProcAddress(hL, "SSL_CTX_set_srp_client_pwd_callback");
		p[30] = GetProcAddress(hL, "TLS_server_method");
		p[31] = GetProcAddress(hL, "SSL_set_verify_depth");
		p[32] = GetProcAddress(hL, "BIO_f_ssl");
		p[33] = GetProcAddress(hL, "DTLS_server_method");
		p[34] = GetProcAddress(hL, "SSL_get_fd");
		p[35] = GetProcAddress(hL, "SSL_CTX_set_ct_validation_callback");
		p[36] = GetProcAddress(hL, "SSL_CONF_cmd_value_type");
		p[37] = GetProcAddress(hL, "SSL_CTX_set_next_proto_select_cb");
		p[38] = GetProcAddress(hL, "SSL_CTX_set_srp_password");
		p[39] = GetProcAddress(hL, "SSL_SESSION_get_protocol_version");
		p[40] = GetProcAddress(hL, "SSL_up_ref");
		p[41] = GetProcAddress(hL, "SSL_CTX_dane_mtype_set");
		p[42] = GetProcAddress(hL, "TLSv1_server_method");
		p[43] = GetProcAddress(hL, "SSL_get_SSL_CTX");
		p[44] = GetProcAddress(hL, "SSL_enable_ct");
		p[45] = GetProcAddress(hL, "SSL_in_before");
		p[46] = GetProcAddress(hL, "SSL_CTX_get_timeout");
		p[47] = GetProcAddress(hL, "SSL_dup_CA_list");
		p[48] = GetProcAddress(hL, "SSL_COMP_add_compression_method");
		p[49] = GetProcAddress(hL, "SSL_get_ciphers");
		p[50] = GetProcAddress(hL, "SSL_get_ex_data");
		p[51] = GetProcAddress(hL, "SSL_CTX_get_client_cert_cb");
		p[52] = GetProcAddress(hL, "SSL_CTX_has_client_custom_ext");
		p[53] = GetProcAddress(hL, "SSL_CTX_set_verify_depth");
		p[54] = GetProcAddress(hL, "SSL_COMP_get_id");
		p[55] = GetProcAddress(hL, "SSL_set1_param");
		p[56] = GetProcAddress(hL, "TLSv1_client_method");
		p[57] = GetProcAddress(hL, "SSL_get_shared_sigalgs");
		p[58] = GetProcAddress(hL, "SSL_CTX_set_tmp_dh_callback");
		p[59] = GetProcAddress(hL, "TLSv1_1_server_method");
		p[60] = GetProcAddress(hL, "SSL_CTX_get_quiet_shutdown");
		p[61] = GetProcAddress(hL, "SSL_CTX_set_ssl_version");
		p[62] = GetProcAddress(hL, "SSL_set_session_ticket_ext_cb");
		p[63] = GetProcAddress(hL, "SSL_CTX_use_serverinfo");
		p[64] = GetProcAddress(hL, "SSL_set_ct_validation_callback");
		p[65] = GetProcAddress(hL, "SSL_CIPHER_get_auth_nid");
		p[66] = GetProcAddress(hL, "SSL_is_server");
		p[67] = GetProcAddress(hL, "SSL_CTX_new");
		p[68] = GetProcAddress(hL, "SSL_CTX_set_psk_server_callback");
		p[69] = GetProcAddress(hL, "SSL_CTX_sess_set_remove_cb");
		p[70] = GetProcAddress(hL, "SSL_SESSION_get0_cipher");
		p[71] = GetProcAddress(hL, "SSL_clear_options");
		p[72] = GetProcAddress(hL, "SSL_CTX_set_alpn_protos");
		p[73] = GetProcAddress(hL, "SSL_CTX_set_next_protos_advertised_cb");
		p[74] = GetProcAddress(hL, "SSL_CTX_set_security_level");
		p[75] = GetProcAddress(hL, "SSL_set_alpn_protos");
		p[76] = GetProcAddress(hL, "SSL_SESSION_get_ticket_lifetime_hint");
		p[77] = GetProcAddress(hL, "SSL_get0_peer_scts");
		p[78] = GetProcAddress(hL, "SSL_ctrl");
		p[79] = GetProcAddress(hL, "SSL_rstate_string_long");
		p[80] = GetProcAddress(hL, "SSL_set_srp_server_param");
		p[81] = GetProcAddress(hL, "SSL_CTX_set_cookie_generate_cb");
		p[82] = GetProcAddress(hL, "SSL_CTX_set1_param");
		p[83] = GetProcAddress(hL, "SSL_set_fd");
		p[84] = GetProcAddress(hL, "SSL_config");
		p[85] = GetProcAddress(hL, "SSL_accept");
		p[86] = GetProcAddress(hL, "SSL_CTX_get0_security_ex_data");
		p[87] = GetProcAddress(hL, "SSL_set_tmp_dh_callback");
		p[88] = GetProcAddress(hL, "SSL_SESSION_print_keylog");
		p[89] = GetProcAddress(hL, "SSL_use_certificate_chain_file");
		p[90] = GetProcAddress(hL, "TLSv1_2_client_method");
		p[91] = GetProcAddress(hL, "SSL_CTX_use_certificate");
		p[92] = GetProcAddress(hL, "SSL_set_session");
		p[93] = GetProcAddress(hL, "SSL_use_psk_identity_hint");
		p[94] = GetProcAddress(hL, "SSL_get_shared_ciphers");
		p[95] = GetProcAddress(hL, "PEM_read_bio_SSL_SESSION");
		p[96] = GetProcAddress(hL, "SSL_get_current_expansion");
		p[97] = GetProcAddress(hL, "SSL_CTX_ct_is_enabled");
		p[98] = GetProcAddress(hL, "d2i_SSL_SESSION");
		p[99] = GetProcAddress(hL, "SSL_ct_is_enabled");
		p[100] = GetProcAddress(hL, "SSL_CTX_set_srp_username_callback");
		p[101] = GetProcAddress(hL, "SRP_Calc_A_param");
		p[102] = GetProcAddress(hL, "BIO_new_ssl_connect");
		p[103] = GetProcAddress(hL, "SSL_get_servername");
		p[104] = GetProcAddress(hL, "DTLSv1_2_server_method");
		p[105] = GetProcAddress(hL, "SSL_peek");
		p[106] = GetProcAddress(hL, "SSL_add_client_CA");
		p[107] = GetProcAddress(hL, "SSL_read");
		p[108] = GetProcAddress(hL, "TLSv1_2_method");
		p[109] = GetProcAddress(hL, "SSL_free");
		p[110] = GetProcAddress(hL, "SSL_want");
		p[111] = GetProcAddress(hL, "TLS_method");
		p[112] = GetProcAddress(hL, "SSL_set_srp_server_param_pw");
		p[113] = GetProcAddress(hL, "SSL_CTX_set_generate_session_id");
		p[114] = GetProcAddress(hL, "SSL_CTX_get0_ctlog_store");
		p[115] = GetProcAddress(hL, "SSL_CTX_SRP_CTX_init");
		p[116] = GetProcAddress(hL, "SSL_CTX_flush_sessions");
		p[117] = GetProcAddress(hL, "SSL_export_keying_material");
		p[118] = GetProcAddress(hL, "SSL_SESSION_get_time");
		p[119] = GetProcAddress(hL, "SSL_CTX_get_verify_depth");
		p[120] = GetProcAddress(hL, "SSL_CTX_get_ex_data");
		p[121] = GetProcAddress(hL, "i2d_SSL_SESSION");
		p[122] = GetProcAddress(hL, "SSL_CTX_dane_set_flags");
		p[123] = GetProcAddress(hL, "SSL_get_read_ahead");
		p[124] = GetProcAddress(hL, "SSL_SESSION_print_fp");
		p[125] = GetProcAddress(hL, "SSL_get_client_ciphers");
		p[126] = GetProcAddress(hL, "SSL_CTX_set_security_callback");
		p[127] = GetProcAddress(hL, "SSL_CTX_get_security_callback");
		p[128] = GetProcAddress(hL, "DTLSv1_server_method");
		p[129] = GetProcAddress(hL, "SSL_CTX_set_default_passwd_cb_userdata");
		p[130] = GetProcAddress(hL, "SSL_CTX_use_RSAPrivateKey_ASN1");
		p[131] = GetProcAddress(hL, "SSL_CTX_get_default_passwd_cb");
		p[132] = GetProcAddress(hL, "SSL_use_certificate");
		p[133] = GetProcAddress(hL, "SSL_SESSION_has_ticket");
		p[134] = GetProcAddress(hL, "SSL_get_all_async_fds");
		p[135] = GetProcAddress(hL, "SSL_connect");
		p[136] = GetProcAddress(hL, "SSL_get_client_random");
		p[137] = GetProcAddress(hL, "SSL_CONF_CTX_set_flags");
		p[138] = GetProcAddress(hL, "SSL_CTX_add_server_custom_ext");
		p[139] = GetProcAddress(hL, "SSL_CTX_get_options");
		p[140] = GetProcAddress(hL, "SSL_CTX_get_ciphers");
		p[141] = GetProcAddress(hL, "DTLS_method");
		p[142] = GetProcAddress(hL, "BIO_new_buffer_ssl_connect");
		p[143] = GetProcAddress(hL, "SSL_SESSION_get_master_key");
		p[144] = GetProcAddress(hL, "SSL_CTX_set_srp_cb_arg");
		p[145] = GetProcAddress(hL, "SSL_set_default_passwd_cb");
		p[146] = GetProcAddress(hL, "BIO_ssl_copy_session_id");
		p[147] = GetProcAddress(hL, "SSL_CTX_dane_clear_flags");
		p[148] = GetProcAddress(hL, "SSL_CONF_CTX_set_ssl");
		p[149] = GetProcAddress(hL, "SSL_CTX_callback_ctrl");
		p[150] = GetProcAddress(hL, "SSL_get_session");
		p[151] = GetProcAddress(hL, "SSL_CTX_SRP_CTX_free");
		p[152] = GetProcAddress(hL, "SSL_get0_peername");
		p[153] = GetProcAddress(hL, "SSL_SESSION_get0_id_context");
		p[154] = GetProcAddress(hL, "SSL_CTX_set_trust");
		p[155] = GetProcAddress(hL, "SSL_CTX_enable_ct");
		p[156] = GetProcAddress(hL, "SSL_is_dtls");
		p[157] = GetProcAddress(hL, "SSL_pending");
		p[158] = GetProcAddress(hL, "SSL_version");
		p[159] = GetProcAddress(hL, "SSL_in_init");
		p[160] = GetProcAddress(hL, "SSL_session_reused");
		p[161] = GetProcAddress(hL, "SSL_CTX_ctrl");
		p[162] = GetProcAddress(hL, "SSL_CTX_set_ctlog_list_file");
		p[163] = GetProcAddress(hL, "SSL_check_private_key");
		p[164] = GetProcAddress(hL, "SSL_CTX_set_cert_verify_callback");
		p[165] = GetProcAddress(hL, "SSL_set_security_level");
		p[166] = GetProcAddress(hL, "SSL_clear");
		p[167] = GetProcAddress(hL, "SSL_CTX_check_private_key");
		p[168] = GetProcAddress(hL, "SSL_CTX_free");
		p[169] = GetProcAddress(hL, "SSL_CIPHER_get_id");
		p[170] = GetProcAddress(hL, "SSL_renegotiate_abbreviated");
		p[171] = GetProcAddress(hL, "SSL_CONF_cmd");
		p[172] = GetProcAddress(hL, "SSL_CTX_set0_ctlog_store");
		p[173] = GetProcAddress(hL, "SSL_set_default_read_buffer_len");
		p[174] = GetProcAddress(hL, "SSL_CTX_config");
		p[175] = GetProcAddress(hL, "SSL_set_verify");
		p[176] = GetProcAddress(hL, "SSL_dup");
		p[177] = GetProcAddress(hL, "SSL_get_finished");
		p[178] = GetProcAddress(hL, "SSL_CONF_CTX_clear_flags");
		p[179] = GetProcAddress(hL, "SSL_CTX_set0_security_ex_data");
		p[180] = GetProcAddress(hL, "SSL_new");
		p[181] = GetProcAddress(hL, "SSL_SESSION_set_timeout");
		p[182] = GetProcAddress(hL, "SSL_set_verify_result");
		p[183] = GetProcAddress(hL, "SSL_CTX_set_alpn_select_cb");
		p[184] = GetProcAddress(hL, "SSL_CTX_get0_certificate");
		p[185] = GetProcAddress(hL, "SSL_get_options");
		p[186] = GetProcAddress(hL, "SSL_get_wfd");
		p[187] = GetProcAddress(hL, "SSL_get_rfd");
		p[188] = GetProcAddress(hL, "SSL_get_version");
		p[189] = GetProcAddress(hL, "SSL_set_default_passwd_cb_userdata");
		p[190] = GetProcAddress(hL, "SSL_CTX_set_srp_verify_param_callback");
		p[191] = GetProcAddress(hL, "SSL_SESSION_get0_ticket");
		p[192] = GetProcAddress(hL, "SSL_client_version");
		p[193] = GetProcAddress(hL, "SSL_get_verify_callback");
		p[194] = GetProcAddress(hL, "SSL_CTX_set_session_id_context");
		p[195] = GetProcAddress(hL, "SSL_use_RSAPrivateKey");
		p[196] = GetProcAddress(hL, "SSL_get_ssl_method");
		p[197] = GetProcAddress(hL, "TLSv1_1_client_method");
		p[198] = GetProcAddress(hL, "SSL_get_peer_certificate");
		p[199] = GetProcAddress(hL, "SSL_extension_supported");
		p[200] = GetProcAddress(hL, "TLSv1_1_method");
		p[201] = GetProcAddress(hL, "SSL_CTX_use_PrivateKey_ASN1");
		p[202] = GetProcAddress(hL, "OPENSSL_init_ssl");
		p[203] = GetProcAddress(hL, "SSL_CTX_remove_session");
		p[204] = GetProcAddress(hL, "SSL_get_verify_result");
		p[205] = GetProcAddress(hL, "SSL_SRP_CTX_free");
		p[206] = GetProcAddress(hL, "SSL_SRP_CTX_init");
		p[207] = GetProcAddress(hL, "SSL_CTX_set_info_callback");
		p[208] = GetProcAddress(hL, "SSL_get_psk_identity");
		p[209] = GetProcAddress(hL, "SSL_set_cipher_list");
		p[210] = GetProcAddress(hL, "SSL_CTX_up_ref");
		p[211] = GetProcAddress(hL, "SSL_CTX_use_PrivateKey_file");
		p[212] = GetProcAddress(hL, "SSL_set_client_CA_list");
		p[213] = GetProcAddress(hL, "SSL_use_certificate_ASN1");
		p[214] = GetProcAddress(hL, "SSL_CTX_set_default_ctlog_list_file");
		p[215] = GetProcAddress(hL, "SSL_CTX_set_default_verify_dir");
		p[216] = GetProcAddress(hL, "SSL_SESSION_free");
		p[217] = GetProcAddress(hL, "SSL_waiting_for_async");
		p[218] = GetProcAddress(hL, "SSL_CTX_set_ex_data");
		p[219] = GetProcAddress(hL, "SSL_set_generate_session_id");
		p[220] = GetProcAddress(hL, "SSL_get_security_callback");
		p[221] = GetProcAddress(hL, "SSL_rstate_string");
		p[222] = GetProcAddress(hL, "SSL_CTX_get_default_passwd_cb_userdata");
		p[223] = GetProcAddress(hL, "SSL_has_matching_session_id");
		p[224] = GetProcAddress(hL, "SSL_SESSION_get_ex_data");
		p[225] = GetProcAddress(hL, "SSL_set_SSL_CTX");
		p[226] = GetProcAddress(hL, "SSL_set_not_resumable_session_callback");
		p[227] = GetProcAddress(hL, "SSL_set_purpose");
		p[228] = GetProcAddress(hL, "SSL_select_next_proto");
		p[229] = GetProcAddress(hL, "SSL_use_certificate_file");
		p[230] = GetProcAddress(hL, "SSL_CONF_CTX_finish");
		p[231] = GetProcAddress(hL, "SSL_CTX_set_client_cert_cb");
		p[232] = GetProcAddress(hL, "SSL_CTX_get_verify_mode");
		p[233] = GetProcAddress(hL, "SSL_set_info_callback");
		p[234] = GetProcAddress(hL, "SSL_CTX_add_client_custom_ext");
		p[235] = GetProcAddress(hL, "SSL_set_read_ahead");
		p[236] = GetProcAddress(hL, "SSL_state_string_long");
		p[237] = GetProcAddress(hL, "SSL_COMP_get_compression_methods");
		p[238] = GetProcAddress(hL, "SSL_CTX_sessions");
		p[239] = GetProcAddress(hL, "SSL_get_srtp_profiles");
		p[240] = GetProcAddress(hL, "SSL_renegotiate");
		p[241] = GetProcAddress(hL, "SSL_CONF_CTX_free");
		p[242] = GetProcAddress(hL, "SSL_CTX_set_cert_store");
		p[243] = GetProcAddress(hL, "PEM_read_SSL_SESSION");
		p[244] = GetProcAddress(hL, "SSL_CTX_get_info_callback");
		p[245] = GetProcAddress(hL, "SSL_CTX_use_certificate_file");
		p[246] = GetProcAddress(hL, "SSL_get_info_callback");
		p[247] = GetProcAddress(hL, "SSL_get_verify_depth");
		p[248] = GetProcAddress(hL, "SSL_CTX_set_srp_strength");
		p[249] = GetProcAddress(hL, "TLSv1_method");
		p[250] = GetProcAddress(hL, "SSL_copy_session_id");
		p[251] = GetProcAddress(hL, "SSL_get_servername_type");
		p[252] = GetProcAddress(hL, "SSL_CTX_set_psk_client_callback");
		p[253] = GetProcAddress(hL, "SSL_get_peer_finished");
		p[254] = GetProcAddress(hL, "SSL_COMP_get0_name");
		p[255] = GetProcAddress(hL, "TLS_client_method");
		p[256] = GetProcAddress(hL, "SSL_set_debug");
		p[257] = GetProcAddress(hL, "SSL_dane_enable");
		p[258] = GetProcAddress(hL, "SSL_set_ssl_method");
		p[259] = GetProcAddress(hL, "SSL_COMP_set0_compression_methods");
		p[260] = GetProcAddress(hL, "SSL_get_current_compression");
		p[261] = GetProcAddress(hL, "SSL_CTX_set_srp_username");
		p[262] = GetProcAddress(hL, "SSL_CTX_use_certificate_ASN1");
		p[263] = GetProcAddress(hL, "SSL_CIPHER_find");
		p[264] = GetProcAddress(hL, "SSL_renegotiate_pending");
		p[265] = GetProcAddress(hL, "SSL_CTX_get_verify_callback");
		p[266] = GetProcAddress(hL, "SSL_CIPHER_description");
		p[267] = GetProcAddress(hL, "DTLS_client_method");
		p[268] = GetProcAddress(hL, "SSL_CTX_set_cookie_verify_cb");
		p[269] = GetProcAddress(hL, "BIO_new_ssl");
		p[270] = GetProcAddress(hL, "SSL_set_bio");
		p[271] = GetProcAddress(hL, "SSL_set_security_callback");
		p[272] = GetProcAddress(hL, "SSL_get0_dane");
		p[273] = GetProcAddress(hL, "SSL_set0_wbio");
		p[274] = GetProcAddress(hL, "SSL_SESSION_set_time");
		p[275] = GetProcAddress(hL, "SSL_get_peer_cert_chain");
		p[276] = GetProcAddress(hL, "SSL_get0_param");
		p[277] = GetProcAddress(hL, "SSL_add1_host");
		p[278] = GetProcAddress(hL, "SSL_shutdown");
		p[279] = GetProcAddress(hL, "SSL_state_string");
		p[280] = GetProcAddress(hL, "SSL_set1_host");
		p[281] = GetProcAddress(hL, "SSL_set0_rbio");
		p[282] = GetProcAddress(hL, "SSL_get1_supported_ciphers");
		p[283] = GetProcAddress(hL, "SSL_get0_next_proto_negotiated");
		p[284] = GetProcAddress(hL, "SSL_get0_alpn_selected");
		p[285] = GetProcAddress(hL, "SSL_get_psk_identity_hint");
		p[286] = GetProcAddress(hL, "SSL_set_shutdown");
		p[287] = GetProcAddress(hL, "SSL_CTX_load_verify_locations");
		p[288] = GetProcAddress(hL, "SSL_set_session_secret_cb");
		p[289] = GetProcAddress(hL, "SSL_CTX_dane_enable");
		p[290] = GetProcAddress(hL, "SSL_CTX_sess_get_remove_cb");
		p[291] = GetProcAddress(hL, "SSL_alert_desc_string");
		p[292] = GetProcAddress(hL, "SSL_CIPHER_is_aead");
		p[293] = GetProcAddress(hL, "SSL_SESSION_get_compress_id");
		p[294] = GetProcAddress(hL, "SSL_CTX_use_psk_identity_hint");
		p[295] = GetProcAddress(hL, "SSL_SESSION_get0_peer");
		p[296] = GetProcAddress(hL, "SSL_set0_security_ex_data");
		p[297] = GetProcAddress(hL, "SSL_SESSION_set1_id");
		p[298] = GetProcAddress(hL, "SSL_SESSION_set_ex_data");
		p[299] = GetProcAddress(hL, "SSL_CTX_sess_get_new_cb");
		p[300] = GetProcAddress(hL, "SSL_CIPHER_get_digest_nid");
		p[301] = GetProcAddress(hL, "SSL_CIPHER_get_version");
		p[302] = GetProcAddress(hL, "SSL_CTX_add_session");
		p[303] = GetProcAddress(hL, "SSL_CTX_set_verify");
		p[304] = GetProcAddress(hL, "SSL_set_quiet_shutdown");
		p[305] = GetProcAddress(hL, "SSL_CTX_set_msg_callback");
		p[306] = GetProcAddress(hL, "SSL_CIPHER_get_bits");
		p[307] = GetProcAddress(hL, "SSL_set_psk_client_callback");
		p[308] = GetProcAddress(hL, "PEM_write_SSL_SESSION");
		p[309] = GetProcAddress(hL, "SSL_set_wfd");
		p[310] = GetProcAddress(hL, "SSL_get_shutdown");
		p[311] = GetProcAddress(hL, "SSL_CTX_set_default_verify_paths");
		p[312] = GetProcAddress(hL, "SSL_get_rbio");
		p[313] = GetProcAddress(hL, "SSL_get_wbio");
		p[314] = GetProcAddress(hL, "SSL_set_rfd");
		p[315] = GetProcAddress(hL, "SSL_get0_security_ex_data");
		p[316] = GetProcAddress(hL, "SSL_CTX_get0_param");
		p[317] = GetProcAddress(hL, "SSL_CTX_use_certificate_chain_file");
		p[318] = GetProcAddress(hL, "SSL_CONF_cmd_argv");
		p[319] = GetProcAddress(hL, "SSL_get_srp_username");
		p[320] = GetProcAddress(hL, "SSL_use_PrivateKey_ASN1");
		p[321] = GetProcAddress(hL, "SSL_get_srp_userinfo");
		p[322] = GetProcAddress(hL, "SSL_get_certificate");
		p[323] = GetProcAddress(hL, "SSL_do_handshake");
		p[324] = GetProcAddress(hL, "SSL_CTX_set_tlsext_use_srtp");
		p[325] = GetProcAddress(hL, "DTLSv1_client_method");
		p[326] = GetProcAddress(hL, "BIO_ssl_shutdown");
		p[327] = GetProcAddress(hL, "SSL_CTX_set_client_cert_engine");
		p[328] = GetProcAddress(hL, "SSL_get_default_timeout");
		p[329] = GetProcAddress(hL, "SSL_CTX_set_default_verify_file");
		p[330] = GetProcAddress(hL, "SSL_SESSION_up_ref");
		p[331] = GetProcAddress(hL, "SSL_dane_set_flags");
		p[332] = GetProcAddress(hL, "SSL_get1_session");
		p[333] = GetProcAddress(hL, "SSL_get_default_passwd_cb_userdata");
		p[334] = GetProcAddress(hL, "SSL_CTX_get_cert_store");
		p[335] = GetProcAddress(hL, "SSL_SESSION_print");
		p[336] = GetProcAddress(hL, "SSL_get_security_level");
		p[337] = GetProcAddress(hL, "SSL_set_trust");
		p[338] = GetProcAddress(hL, "SSL_write");
		p[339] = GetProcAddress(hL, "SSL_CIPHER_get_name");
		p[340] = GetProcAddress(hL, "SSL_COMP_get_name");
		p[341] = GetProcAddress(hL, "SSL_add_file_cert_subjects_to_stack");
		p[342] = GetProcAddress(hL, "SSL_get_verify_mode");
		p[343] = GetProcAddress(hL, "SSL_CTX_get_ssl_method");
		p[344] = GetProcAddress(hL, "DTLSv1_listen");
		p[345] = GetProcAddress(hL, "SSL_CONF_CTX_new");
		p[346] = GetProcAddress(hL, "SSL_CONF_CTX_set1_prefix");
		p[347] = GetProcAddress(hL, "DTLSv1_2_method");
		p[348] = GetProcAddress(hL, "SSL_CONF_CTX_set_ssl_ctx");
		p[349] = GetProcAddress(hL, "SSL_get_cipher_list");
		p[350] = GetProcAddress(hL, "SSL_get_quiet_shutdown");
		p[351] = GetProcAddress(hL, "SSL_add_ssl_module");
		p[352] = GetProcAddress(hL, "SSL_alert_desc_string_long");
		p[353] = GetProcAddress(hL, "DTLSv1_method");
		p[354] = GetProcAddress(hL, "SSL_CIPHER_get_cipher_nid");
		p[355] = GetProcAddress(hL, "SSL_CTX_set_default_read_buffer_len");
		p[356] = GetProcAddress(hL, "PEM_write_bio_SSL_SESSION");
		p[357] = GetProcAddress(hL, "SSL_get0_dane_authority");
		p[358] = GetProcAddress(hL, "SSL_set_psk_server_callback");
		p[359] = GetProcAddress(hL, "SSL_CTX_get_security_level");
		p[360] = GetProcAddress(hL, "SSL_SESSION_set1_id_context");
		p[361] = GetProcAddress(hL, "SSL_get_default_passwd_cb");
		p[362] = GetProcAddress(hL, "SSL_set_session_id_context");
		p[363] = GetProcAddress(hL, "SSL_CTX_use_RSAPrivateKey_file");
		p[364] = GetProcAddress(hL, "SSL_CTX_add_client_CA");
		p[365] = GetProcAddress(hL, "SSL_set_msg_callback");
		p[366] = GetProcAddress(hL, "SSL_SESSION_new");
		p[367] = GetProcAddress(hL, "SSL_CTX_get_client_CA_list");
		p[368] = GetProcAddress(hL, "SSL_CTX_set_timeout");
		p[369] = GetProcAddress(hL, "SSL_SESSION_get0_hostname");
		p[370] = GetProcAddress(hL, "SSL_callback_ctrl");
		p[371] = GetProcAddress(hL, "SSL_get0_verified_chain");
		p[372] = GetProcAddress(hL, "SSL_check_chain");
		p[373] = GetProcAddress(hL, "SSL_has_pending");
		p[374] = GetProcAddress(hL, "SSL_use_PrivateKey_file");
		p[375] = GetProcAddress(hL, "SSL_set_ex_data");
		p[376] = GetProcAddress(hL, "SSL_set_cert_cb");
		p[377] = GetProcAddress(hL, "SSL_set_options");
		p[378] = GetProcAddress(hL, "SSL_CTX_use_PrivateKey");
		p[379] = GetProcAddress(hL, "SSL_CTX_set_quiet_shutdown");
		p[380] = GetProcAddress(hL, "SSL_alert_type_string_long");
		p[381] = GetProcAddress(hL, "SSL_CTX_set_cert_cb");
		p[382] = GetProcAddress(hL, "SSL_alert_type_string");
		p[383] = GetProcAddress(hL, "SSL_srp_server_param_with_username");
		p[384] = GetProcAddress(hL, "SSL_SESSION_get_timeout");
		p[385] = GetProcAddress(hL, "SSL_get_selected_srtp_profile");
		p[386] = GetProcAddress(hL, "SSL_get_current_cipher");
		p[387] = GetProcAddress(hL, "SSL_CTX_sess_set_new_cb");
		p[388] = GetProcAddress(hL, "SSL_set_session_ticket_ext");
		p[389] = GetProcAddress(hL, "SSL_CTX_sess_get_get_cb");
		p[390] = GetProcAddress(hL, "SSL_CTX_sess_set_get_cb");
		p[391] = GetProcAddress(hL, "SSL_CTX_set_cipher_list");
		p[392] = GetProcAddress(hL, "SSL_is_init_finished");
		p[393] = GetProcAddress(hL, "SSL_use_RSAPrivateKey_ASN1");
		p[394] = GetProcAddress(hL, "SSL_get_sigalgs");
		p[395] = GetProcAddress(hL, "SSL_SESSION_get_id");
		p[396] = GetProcAddress(hL, "SSL_get_srp_N");
		p[397] = GetProcAddress(hL, "ERR_load_SSL_strings");
		p[398] = GetProcAddress(hL, "SSL_CTX_set_client_CA_list");
		p[399] = GetProcAddress(hL, "SSL_get_srp_g");
		p[400] = GetProcAddress(hL, "SSL_add_dir_cert_subjects_to_stack");
		OpenConsole();
	}
	if (reason == DLL_PROCESS_DETACH)
	{

	}
	return TRUE;
}

extern "C" __declspec(naked) void Proxy_SSL_use_PrivateKey()
{
	__asm
	{
		jmp p[0 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_load_client_CA_file()
{
	__asm
	{
		jmp p[1 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_dane_tlsa_add()
{
	__asm
	{
		jmp p[2 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_privatekey()
{
	__asm
	{
		jmp p[3 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_clear_options()
{
	__asm
	{
		jmp p[4 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_use_RSAPrivateKey_file()
{
	__asm
	{
		jmp p[5 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_DTLSv1_2_client_method()
{
	__asm
	{
		jmp p[6 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_get0_privatekey()
{
	__asm
	{
		jmp p[7 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CIPHER_get_kx_nid()
{
	__asm
	{
		jmp p[8 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_use_serverinfo_file()
{
	__asm
	{
		jmp p[9 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_ex_data_X509_STORE_CTX_idx()
{
	__asm
	{
		jmp p[10 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_dane_clear_flags()
{
	__asm
	{
		jmp p[11 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_TLSv1_2_server_method()
{
	__asm
	{
		jmp p[12 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_state()
{
	__asm
	{
		jmp p[13 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_server_random()
{
	__asm
	{
		jmp p[14 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_default_passwd_cb()
{
	__asm
	{
		jmp p[15 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_purpose()
{
	__asm
	{
		jmp p[16 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_certs_clear()
{
	__asm
	{
		jmp p[17 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_connect_state()
{
	__asm
	{
		jmp p[18 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_use_RSAPrivateKey()
{
	__asm
	{
		jmp p[19 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_error()
{
	__asm
	{
		jmp p[20 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_tlsext_use_srtp()
{
	__asm
	{
		jmp p[21 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_client_CA_list()
{
	__asm
	{
		jmp p[22 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_options()
{
	__asm
	{
		jmp p[23 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_not_resumable_session_callback()
{
	__asm
	{
		jmp p[24 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_accept_state()
{
	__asm
	{
		jmp p[25 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get0_dane_tlsa()
{
	__asm
	{
		jmp p[26 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_changed_async_fds()
{
	__asm
	{
		jmp p[27 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_hostflags()
{
	__asm
	{
		jmp p[28 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_srp_client_pwd_callback()
{
	__asm
	{
		jmp p[29 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_TLS_server_method()
{
	__asm
	{
		jmp p[30 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_verify_depth()
{
	__asm
	{
		jmp p[31 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_BIO_f_ssl()
{
	__asm
	{
		jmp p[32 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_DTLS_server_method()
{
	__asm
	{
		jmp p[33 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_fd()
{
	__asm
	{
		jmp p[34 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_ct_validation_callback()
{
	__asm
	{
		jmp p[35 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CONF_cmd_value_type()
{
	__asm
	{
		jmp p[36 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_next_proto_select_cb()
{
	__asm
	{
		jmp p[37 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_srp_password()
{
	__asm
	{
		jmp p[38 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_SESSION_get_protocol_version()
{
	__asm
	{
		jmp p[39 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_up_ref()
{
	__asm
	{
		jmp p[40 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_dane_mtype_set()
{
	__asm
	{
		jmp p[41 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_TLSv1_server_method()
{
	__asm
	{
		jmp p[42 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_SSL_CTX()
{
	__asm
	{
		jmp p[43 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_enable_ct()
{
	__asm
	{
		jmp p[44 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_in_before()
{
	__asm
	{
		jmp p[45 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_get_timeout()
{
	__asm
	{
		jmp p[46 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_dup_CA_list()
{
	__asm
	{
		jmp p[47 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_COMP_add_compression_method()
{
	__asm
	{
		jmp p[48 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_ciphers()
{
	__asm
	{
		jmp p[49 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_ex_data()
{
	__asm
	{
		jmp p[50 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_get_client_cert_cb()
{
	__asm
	{
		jmp p[51 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_has_client_custom_ext()
{
	__asm
	{
		jmp p[52 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_verify_depth()
{
	__asm
	{
		jmp p[53 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_COMP_get_id()
{
	__asm
	{
		jmp p[54 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set1_param()
{
	__asm
	{
		jmp p[55 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_TLSv1_client_method()
{
	__asm
	{
		jmp p[56 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_shared_sigalgs()
{
	__asm
	{
		jmp p[57 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_tmp_dh_callback()
{
	__asm
	{
		jmp p[58 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_TLSv1_1_server_method()
{
	__asm
	{
		jmp p[59 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_get_quiet_shutdown()
{
	__asm
	{
		jmp p[60 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_ssl_version()
{
	__asm
	{
		jmp p[61 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_session_ticket_ext_cb()
{
	__asm
	{
		jmp p[62 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_use_serverinfo()
{
	__asm
	{
		jmp p[63 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_ct_validation_callback()
{
	__asm
	{
		jmp p[64 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CIPHER_get_auth_nid()
{
	__asm
	{
		jmp p[65 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_is_server()
{
	__asm
	{
		jmp p[66 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_new()
{
	__asm
	{
		jmp p[67 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_psk_server_callback()
{
	__asm
	{
		jmp p[68 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_sess_set_remove_cb()
{
	__asm
	{
		jmp p[69 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_SESSION_get0_cipher()
{
	__asm
	{
		jmp p[70 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_clear_options()
{
	__asm
	{
		jmp p[71 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_alpn_protos()
{
	__asm
	{
		jmp p[72 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_next_protos_advertised_cb()
{
	__asm
	{
		jmp p[73 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_security_level()
{
	__asm
	{
		jmp p[74 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_alpn_protos()
{
	__asm
	{
		jmp p[75 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_SESSION_get_ticket_lifetime_hint()
{
	__asm
	{
		jmp p[76 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get0_peer_scts()
{
	__asm
	{
		jmp p[77 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_ctrl()
{
	__asm
	{
		jmp p[78 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_rstate_string_long()
{
	__asm
	{
		jmp p[79 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_srp_server_param()
{
	__asm
	{
		jmp p[80 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_cookie_generate_cb()
{
	__asm
	{
		jmp p[81 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set1_param()
{
	__asm
	{
		jmp p[82 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_fd()
{
	__asm
	{
		jmp p[83 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_config()
{
	__asm
	{
		jmp p[84 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_accept()
{
	__asm
	{
		jmp p[85 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_get0_security_ex_data()
{
	__asm
	{
		jmp p[86 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_tmp_dh_callback()
{
	__asm
	{
		jmp p[87 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_SESSION_print_keylog()
{
	__asm
	{
		jmp p[88 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_use_certificate_chain_file()
{
	__asm
	{
		jmp p[89 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_TLSv1_2_client_method()
{
	__asm
	{
		jmp p[90 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_use_certificate()
{
	__asm
	{
		jmp p[91 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_session()
{
	__asm
	{
		jmp p[92 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_use_psk_identity_hint()
{
	__asm
	{
		jmp p[93 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_shared_ciphers()
{
	__asm
	{
		jmp p[94 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_PEM_read_bio_SSL_SESSION()
{
	__asm
	{
		jmp p[95 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_current_expansion()
{
	__asm
	{
		jmp p[96 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_ct_is_enabled()
{
	__asm
	{
		jmp p[97 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_d2i_SSL_SESSION()
{
	__asm
	{
		jmp p[98 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_ct_is_enabled()
{
	__asm
	{
		jmp p[99 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_srp_username_callback()
{
	__asm
	{
		jmp p[100 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SRP_Calc_A_param()
{
	__asm
	{
		jmp p[101 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_BIO_new_ssl_connect()
{
	__asm
	{
		jmp p[102 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_servername()
{
	__asm
	{
		jmp p[103 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_DTLSv1_2_server_method()
{
	__asm
	{
		jmp p[104 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_peek()
{
	__asm
	{
		jmp p[105 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_add_client_CA()
{
	__asm
	{
		jmp p[106 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_read()
{
	__asm
	{
		pop data;
		push data;
		pushad;
	}
	fprintf(logfile, "[READ]\n\n%s\n\n*-*-*-*-*-*-*-*-*\n", (char *)data);
	printf("SSL_read was used. argument data:\n");
	hexdump(data, 0x31);
	__asm
	{
		popad;
		jmp p[107 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_TLSv1_2_method()
{
	__asm
	{
		jmp p[108 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_free()
{
	__asm
	{
		jmp p[109 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_want()
{
	__asm
	{
		jmp p[110 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_TLS_method()
{
	__asm
	{
		jmp p[111 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_srp_server_param_pw()
{
	__asm
	{
		jmp p[112 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_generate_session_id()
{
	__asm
	{
		jmp p[113 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_get0_ctlog_store()
{
	__asm
	{
		jmp p[114 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_SRP_CTX_init()
{
	__asm
	{
		jmp p[115 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_flush_sessions()
{
	__asm
	{
		jmp p[116 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_export_keying_material()
{
	__asm
	{
		jmp p[117 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_SESSION_get_time()
{
	__asm
	{
		jmp p[118 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_get_verify_depth()
{
	__asm
	{
		jmp p[119 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_get_ex_data()
{
	__asm
	{
		jmp p[120 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_i2d_SSL_SESSION()
{
	__asm
	{
		jmp p[121 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_dane_set_flags()
{
	__asm
	{
		jmp p[122 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_read_ahead()
{
	__asm
	{
		jmp p[123 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_SESSION_print_fp()
{
	__asm
	{
		jmp p[124 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_client_ciphers()
{
	__asm
	{
		jmp p[125 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_security_callback()
{
	__asm
	{
		jmp p[126 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_get_security_callback()
{
	__asm
	{
		jmp p[127 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_DTLSv1_server_method()
{
	__asm
	{
		jmp p[128 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_default_passwd_cb_userdata()
{
	__asm
	{
		jmp p[129 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_use_RSAPrivateKey_ASN1()
{
	__asm
	{
		jmp p[130 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_get_default_passwd_cb()
{
	__asm
	{
		jmp p[131 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_use_certificate()
{
	__asm
	{
		jmp p[132 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_SESSION_has_ticket()
{
	__asm
	{
		jmp p[133 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_all_async_fds()
{
	__asm
	{
		jmp p[134 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_connect()
{
	__asm
	{
		jmp p[135 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_client_random()
{
	__asm
	{
		jmp p[136 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CONF_CTX_set_flags()
{
	__asm
	{
		jmp p[137 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_add_server_custom_ext()
{
	__asm
	{
		jmp p[138 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_get_options()
{
	__asm
	{
		jmp p[139 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_get_ciphers()
{
	__asm
	{
		jmp p[140 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_DTLS_method()
{
	__asm
	{
		jmp p[141 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_BIO_new_buffer_ssl_connect()
{
	__asm
	{
		jmp p[142 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_SESSION_get_master_key()
{
	__asm
	{
		jmp p[143 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_srp_cb_arg()
{
	__asm
	{
		jmp p[144 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_default_passwd_cb()
{
	__asm
	{
		jmp p[145 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_BIO_ssl_copy_session_id()
{
	__asm
	{
		jmp p[146 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_dane_clear_flags()
{
	__asm
	{
		jmp p[147 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CONF_CTX_set_ssl()
{
	__asm
	{
		jmp p[148 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_callback_ctrl()
{
	__asm
	{
		jmp p[149 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_session()
{
	__asm
	{
		jmp p[150 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_SRP_CTX_free()
{
	__asm
	{
		jmp p[151 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get0_peername()
{
	__asm
	{
		jmp p[152 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_SESSION_get0_id_context()
{
	__asm
	{
		jmp p[153 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_trust()
{
	__asm
	{
		jmp p[154 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_enable_ct()
{
	__asm
	{
		jmp p[155 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_is_dtls()
{
	__asm
	{
		jmp p[156 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_pending()
{
	__asm
	{
		jmp p[157 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_version()
{
	__asm
	{
		jmp p[158 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_in_init()
{
	__asm
	{
		jmp p[159 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_session_reused()
{
	__asm
	{
		jmp p[160 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_ctrl()
{
	__asm
	{
		jmp p[161 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_ctlog_list_file()
{
	__asm
	{
		jmp p[162 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_check_private_key()
{
	__asm
	{
		jmp p[163 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_cert_verify_callback()
{
	__asm
	{
		jmp p[164 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_security_level()
{
	__asm
	{
		jmp p[165 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_clear()
{
	__asm
	{
		jmp p[166 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_check_private_key()
{
	__asm
	{
		jmp p[167 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_free()
{
	__asm
	{
		jmp p[168 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CIPHER_get_id()
{
	__asm
	{
		jmp p[169 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_renegotiate_abbreviated()
{
	__asm
	{
		jmp p[170 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CONF_cmd()
{
	__asm
	{
		jmp p[171 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set0_ctlog_store()
{
	__asm
	{
		jmp p[172 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_default_read_buffer_len()
{
	__asm
	{
		jmp p[173 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_config()
{
	__asm
	{
		jmp p[174 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_verify()
{
	__asm
	{
		jmp p[175 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_dup()
{
	__asm
	{
		jmp p[176 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_finished()
{
	__asm
	{
		jmp p[177 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CONF_CTX_clear_flags()
{
	__asm
	{
		jmp p[178 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set0_security_ex_data()
{
	__asm
	{
		jmp p[179 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_new()
{
	__asm
	{
		jmp p[180 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_SESSION_set_timeout()
{
	__asm
	{
		jmp p[181 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_verify_result()
{
	__asm
	{
		jmp p[182 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_alpn_select_cb()
{
	__asm
	{
		jmp p[183 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_get0_certificate()
{
	__asm
	{
		jmp p[184 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_options()
{
	__asm
	{
		jmp p[185 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_wfd()
{
	__asm
	{
		jmp p[186 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_rfd()
{
	__asm
	{
		jmp p[187 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_version()
{
	__asm
	{
		jmp p[188 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_default_passwd_cb_userdata()
{
	__asm
	{
		jmp p[189 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_srp_verify_param_callback()
{
	__asm
	{
		jmp p[190 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_SESSION_get0_ticket()
{
	__asm
	{
		jmp p[191 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_client_version()
{
	__asm
	{
		jmp p[192 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_verify_callback()
{
	__asm
	{
		jmp p[193 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_session_id_context()
{
	__asm
	{
		jmp p[194 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_use_RSAPrivateKey()
{
	__asm
	{
		jmp p[195 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_ssl_method()
{
	__asm
	{
		jmp p[196 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_TLSv1_1_client_method()
{
	__asm
	{
		jmp p[197 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_peer_certificate()
{
	__asm
	{
		jmp p[198 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_extension_supported()
{
	__asm
	{
		jmp p[199 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_TLSv1_1_method()
{
	__asm
	{
		jmp p[200 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_use_PrivateKey_ASN1()
{
	__asm
	{
		jmp p[201 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_OPENSSL_init_ssl()
{
	__asm
	{
		jmp p[202 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_remove_session()
{
	__asm
	{
		jmp p[203 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_verify_result()
{
	__asm
	{
		jmp p[204 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_SRP_CTX_free()
{
	__asm
	{
		jmp p[205 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_SRP_CTX_init()
{
	__asm
	{
		jmp p[206 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_info_callback()
{
	__asm
	{
		jmp p[207 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_psk_identity()
{
	__asm
	{
		jmp p[208 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_cipher_list()
{
	__asm
	{
		jmp p[209 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_up_ref()
{
	__asm
	{
		jmp p[210 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_use_PrivateKey_file()
{
	__asm
	{
		jmp p[211 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_client_CA_list()
{
	__asm
	{
		jmp p[212 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_use_certificate_ASN1()
{
	__asm
	{
		jmp p[213 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_default_ctlog_list_file()
{
	__asm
	{
		jmp p[214 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_default_verify_dir()
{
	__asm
	{
		jmp p[215 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_SESSION_free()
{
	__asm
	{
		jmp p[216 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_waiting_for_async()
{
	__asm
	{
		jmp p[217 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_ex_data()
{
	__asm
	{
		jmp p[218 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_generate_session_id()
{
	__asm
	{
		jmp p[219 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_security_callback()
{
	__asm
	{
		jmp p[220 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_rstate_string()
{
	__asm
	{
		jmp p[221 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_get_default_passwd_cb_userdata()
{
	__asm
	{
		jmp p[222 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_has_matching_session_id()
{
	__asm
	{
		jmp p[223 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_SESSION_get_ex_data()
{
	__asm
	{
		jmp p[224 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_SSL_CTX()
{
	__asm
	{
		jmp p[225 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_not_resumable_session_callback()
{
	__asm
	{
		jmp p[226 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_purpose()
{
	__asm
	{
		jmp p[227 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_select_next_proto()
{
	__asm
	{
		jmp p[228 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_use_certificate_file()
{
	__asm
	{
		jmp p[229 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CONF_CTX_finish()
{
	__asm
	{
		jmp p[230 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_client_cert_cb()
{
	__asm
	{
		jmp p[231 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_get_verify_mode()
{
	__asm
	{
		jmp p[232 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_info_callback()
{
	__asm
	{
		jmp p[233 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_add_client_custom_ext()
{
	__asm
	{
		jmp p[234 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_read_ahead()
{
	__asm
	{
		jmp p[235 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_state_string_long()
{
	__asm
	{
		jmp p[236 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_COMP_get_compression_methods()
{
	__asm
	{
		jmp p[237 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_sessions()
{
	__asm
	{
		jmp p[238 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_srtp_profiles()
{
	__asm
	{
		jmp p[239 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_renegotiate()
{
	__asm
	{
		jmp p[240 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CONF_CTX_free()
{
	__asm
	{
		jmp p[241 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_cert_store()
{
	__asm
	{
		jmp p[242 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_PEM_read_SSL_SESSION()
{
	__asm
	{
		jmp p[243 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_get_info_callback()
{
	__asm
	{
		jmp p[244 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_use_certificate_file()
{
	__asm
	{
		jmp p[245 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_info_callback()
{
	__asm
	{
		jmp p[246 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_verify_depth()
{
	__asm
	{
		jmp p[247 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_srp_strength()
{
	__asm
	{
		jmp p[248 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_TLSv1_method()
{
	__asm
	{
		jmp p[249 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_copy_session_id()
{
	__asm
	{
		jmp p[250 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_servername_type()
{
	__asm
	{
		jmp p[251 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_psk_client_callback()
{
	__asm
	{
		jmp p[252 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_peer_finished()
{
	__asm
	{
		jmp p[253 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_COMP_get0_name()
{
	__asm
	{
		jmp p[254 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_TLS_client_method()
{
	__asm
	{
		jmp p[255 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_debug()
{
	__asm
	{
		jmp p[256 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_dane_enable()
{
	__asm
	{
		jmp p[257 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_ssl_method()
{
	__asm
	{
		jmp p[258 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_COMP_set0_compression_methods()
{
	__asm
	{
		jmp p[259 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_current_compression()
{
	__asm
	{
		jmp p[260 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_srp_username()
{
	__asm
	{
		jmp p[261 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_use_certificate_ASN1()
{
	__asm
	{
		jmp p[262 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CIPHER_find()
{
	__asm
	{
		jmp p[263 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_renegotiate_pending()
{
	__asm
	{
		jmp p[264 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_get_verify_callback()
{
	__asm
	{
		jmp p[265 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CIPHER_description()
{
	__asm
	{
		jmp p[266 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_DTLS_client_method()
{
	__asm
	{
		jmp p[267 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_cookie_verify_cb()
{
	__asm
	{
		jmp p[268 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_BIO_new_ssl()
{
	__asm
	{
		jmp p[269 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_bio()
{
	__asm
	{
		jmp p[270 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_security_callback()
{
	__asm
	{
		jmp p[271 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get0_dane()
{
	__asm
	{
		jmp p[272 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set0_wbio()
{
	__asm
	{
		jmp p[273 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_SESSION_set_time()
{
	__asm
	{
		jmp p[274 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_peer_cert_chain()
{
	__asm
	{
		jmp p[275 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get0_param()
{
	__asm
	{
		jmp p[276 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_add1_host()
{
	__asm
	{
		jmp p[277 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_shutdown()
{
	__asm
	{
		jmp p[278 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_state_string()
{
	__asm
	{
		jmp p[279 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set1_host()
{
	__asm
	{
		jmp p[280 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set0_rbio()
{
	__asm
	{
		jmp p[281 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get1_supported_ciphers()
{
	__asm
	{
		jmp p[282 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get0_next_proto_negotiated()
{
	__asm
	{
		jmp p[283 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get0_alpn_selected()
{
	__asm
	{
		jmp p[284 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_psk_identity_hint()
{
	__asm
	{
		jmp p[285 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_shutdown()
{
	__asm
	{
		jmp p[286 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_load_verify_locations()
{
	__asm
	{
		jmp p[287 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_session_secret_cb()
{
	__asm
	{
		jmp p[288 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_dane_enable()
{
	__asm
	{
		jmp p[289 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_sess_get_remove_cb()
{
	__asm
	{
		jmp p[290 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_alert_desc_string()
{
	__asm
	{
		jmp p[291 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CIPHER_is_aead()
{
	__asm
	{
		jmp p[292 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_SESSION_get_compress_id()
{
	__asm
	{
		jmp p[293 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_use_psk_identity_hint()
{
	__asm
	{
		jmp p[294 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_SESSION_get0_peer()
{
	__asm
	{
		jmp p[295 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set0_security_ex_data()
{
	__asm
	{
		jmp p[296 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_SESSION_set1_id()
{
	__asm
	{
		jmp p[297 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_SESSION_set_ex_data()
{
	__asm
	{
		jmp p[298 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_sess_get_new_cb()
{
	__asm
	{
		jmp p[299 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CIPHER_get_digest_nid()
{
	__asm
	{
		jmp p[300 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CIPHER_get_version()
{
	__asm
	{
		jmp p[301 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_add_session()
{
	__asm
	{
		jmp p[302 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_verify()
{
	__asm
	{
		jmp p[303 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_quiet_shutdown()
{
	__asm
	{
		jmp p[304 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_msg_callback()
{
	__asm
	{
		jmp p[305 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CIPHER_get_bits()
{
	__asm
	{
		jmp p[306 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_psk_client_callback()
{
	__asm
	{
		jmp p[307 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_PEM_write_SSL_SESSION()
{
	__asm
	{
		jmp p[308 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_wfd()
{
	__asm
	{
		jmp p[309 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_shutdown()
{
	__asm
	{
		jmp p[310 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_default_verify_paths()
{
	__asm
	{
		jmp p[311 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_rbio()
{
	__asm
	{
		jmp p[312 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_wbio()
{
	__asm
	{
		jmp p[313 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_rfd()
{
	__asm
	{
		jmp p[314 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get0_security_ex_data()
{
	__asm
	{
		jmp p[315 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_get0_param()
{
	__asm
	{
		jmp p[316 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_use_certificate_chain_file()
{
	__asm
	{
		jmp p[317 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CONF_cmd_argv()
{
	__asm
	{
		jmp p[318 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_srp_username()
{
	__asm
	{
		jmp p[319 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_use_PrivateKey_ASN1()
{
	__asm
	{
		jmp p[320 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_srp_userinfo()
{
	__asm
	{
		jmp p[321 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_certificate()
{
	__asm
	{
		jmp p[322 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_do_handshake()
{
	__asm
	{
		jmp p[323 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_tlsext_use_srtp()
{
	__asm
	{
		jmp p[324 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_DTLSv1_client_method()
{
	__asm
	{
		jmp p[325 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_BIO_ssl_shutdown()
{
	__asm
	{
		jmp p[326 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_client_cert_engine()
{
	__asm
	{
		jmp p[327 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_default_timeout()
{
	__asm
	{
		jmp p[328 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_default_verify_file()
{
	__asm
	{
		jmp p[329 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_SESSION_up_ref()
{
	__asm
	{
		jmp p[330 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_dane_set_flags()
{
	__asm
	{
		jmp p[331 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get1_session()
{
	__asm
	{
		jmp p[332 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_default_passwd_cb_userdata()
{
	__asm
	{
		jmp p[333 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_get_cert_store()
{
	__asm
	{
		jmp p[334 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_SESSION_print()
{
	__asm
	{
		jmp p[335 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_security_level()
{
	__asm
	{
		jmp p[336 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_trust()
{
	__asm
	{
		jmp p[337 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_write()
{

	__asm
	{
		pop data;
		push data;
		pushad;
	}
	printf("SSL_write was used. argument data:\n");
	fprintf(logfile, "[WRITE]\n\n%s\n\n*-*-*-*-*-*-*-*-*\n", (char *)data);
	hexdump(data, 0x31);
	__asm
	{
		popad;
		jmp p[338 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CIPHER_get_name()
{
	__asm
	{
		jmp p[339 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_COMP_get_name()
{
	__asm
	{
		jmp p[340 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_add_file_cert_subjects_to_stack()
{
	__asm
	{
		jmp p[341 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_verify_mode()
{
	__asm
	{
		jmp p[342 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_get_ssl_method()
{
	__asm
	{
		jmp p[343 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_DTLSv1_listen()
{
	__asm
	{
		jmp p[344 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CONF_CTX_new()
{
	__asm
	{
		jmp p[345 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CONF_CTX_set1_prefix()
{
	__asm
	{
		jmp p[346 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_DTLSv1_2_method()
{
	__asm
	{
		jmp p[347 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CONF_CTX_set_ssl_ctx()
{
	__asm
	{
		jmp p[348 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_cipher_list()
{
	__asm
	{
		jmp p[349 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_quiet_shutdown()
{
	__asm
	{
		jmp p[350 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_add_ssl_module()
{
	__asm
	{
		jmp p[351 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_alert_desc_string_long()
{
	__asm
	{
		jmp p[352 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_DTLSv1_method()
{
	__asm
	{
		jmp p[353 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CIPHER_get_cipher_nid()
{
	__asm
	{
		jmp p[354 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_default_read_buffer_len()
{
	__asm
	{
		jmp p[355 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_PEM_write_bio_SSL_SESSION()
{
	__asm
	{
		jmp p[356 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get0_dane_authority()
{
	__asm
	{
		jmp p[357 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_psk_server_callback()
{
	__asm
	{
		jmp p[358 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_get_security_level()
{
	__asm
	{
		jmp p[359 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_SESSION_set1_id_context()
{
	__asm
	{
		jmp p[360 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_default_passwd_cb()
{
	__asm
	{
		jmp p[361 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_session_id_context()
{
	__asm
	{
		jmp p[362 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_use_RSAPrivateKey_file()
{
	__asm
	{
		jmp p[363 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_add_client_CA()
{
	__asm
	{
		jmp p[364 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_msg_callback()
{
	__asm
	{
		jmp p[365 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_SESSION_new()
{
	__asm
	{
		jmp p[366 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_get_client_CA_list()
{
	__asm
	{
		jmp p[367 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_timeout()
{
	__asm
	{
		jmp p[368 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_SESSION_get0_hostname()
{
	__asm
	{
		jmp p[369 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_callback_ctrl()
{
	__asm
	{
		jmp p[370 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get0_verified_chain()
{
	__asm
	{
		jmp p[371 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_check_chain()
{
	__asm
	{
		jmp p[372 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_has_pending()
{
	__asm
	{
		jmp p[373 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_use_PrivateKey_file()
{
	__asm
	{
		jmp p[374 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_ex_data()
{
	__asm
	{
		jmp p[375 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_cert_cb()
{
	__asm
	{
		jmp p[376 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_options()
{
	__asm
	{
		jmp p[377 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_use_PrivateKey()
{
	__asm
	{
		jmp p[378 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_quiet_shutdown()
{
	__asm
	{
		jmp p[379 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_alert_type_string_long()
{
	__asm
	{
		jmp p[380 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_cert_cb()
{
	__asm
	{
		jmp p[381 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_alert_type_string()
{
	__asm
	{
		jmp p[382 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_srp_server_param_with_username()
{
	__asm
	{
		jmp p[383 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_SESSION_get_timeout()
{
	__asm
	{
		jmp p[384 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_selected_srtp_profile()
{
	__asm
	{
		jmp p[385 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_current_cipher()
{
	__asm
	{
		jmp p[386 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_sess_set_new_cb()
{
	__asm
	{
		jmp p[387 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_set_session_ticket_ext()
{
	__asm
	{
		jmp p[388 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_sess_get_get_cb()
{
	__asm
	{
		jmp p[389 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_sess_set_get_cb()
{
	__asm
	{
		jmp p[390 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_cipher_list()
{
	__asm
	{
		jmp p[391 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_is_init_finished()
{
	__asm
	{
		jmp p[392 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_use_RSAPrivateKey_ASN1()
{
	__asm
	{
		jmp p[393 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_sigalgs()
{
	__asm
	{
		jmp p[394 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_SESSION_get_id()
{
	__asm
	{
		jmp p[395 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_srp_N()
{
	__asm
	{
		jmp p[396 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_ERR_load_SSL_strings()
{
	__asm
	{
		jmp p[397 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_CTX_set_client_CA_list()
{
	__asm
	{
		jmp p[398 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_get_srp_g()
{
	__asm
	{
		jmp p[399 * 4];
	}
}

extern "C" __declspec(naked) void Proxy_SSL_add_dir_cert_subjects_to_stack()
{
	__asm
	{
		jmp p[400 * 4];
	}
}


