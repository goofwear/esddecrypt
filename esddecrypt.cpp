#include <stdio.h>
#include <Windows.h>
#include <WinCrypt.h>
#include <stdio.h>
#include <io.h>
#include <locale.h>

#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

#include "defines.h"

#define ESD_IMAGE_VERSION 0xe00UL
#define ESD_IMAGE_FLAGS ( FLAG_HEADER_COMPRESSION | FLAG_HEADER_RP_FIX | FLAG_HEADER_COMPRESS_LZMS )

const WCHAR *known_base64_crypto_keys[] = {
    // Windows 8 & 8.1
    L"BwIAAACkAABSU0EyAAgAAAEAAQD1uPI7ZDwMsPbQSyrXDZblLcBf9VNiOSYNOWsLhHkyqpipeo7uOdXrONjHU2MQLZyobpVyunYMUgmU8vaBRMJHyW+Dj0xJqb9urwYFfoExrVDQVpDOOy0kDG1cGus8utua9d64n4vwRwHM4Mtta7T4sQ/o1J9L4QYUQ9xvDc8sWSA2T47n0y3Sj4OCY0RQeQFMke6+3cdnsAYevx4wL8aRS9PKHa8ItyazQJLxmKpb8HnOJn2Ws2ycr4ClGAjT4mqaflEvZ93DWZrk2RyWos0y20NmQ7mAWrVMSSuuINExN5PcvmAuMmvU2N/sCyNa2jPlaQTjJtm0DKoADRfu+W66vTHTwyJ+P2vKQv7HtbsNZMXN0cnhxSnUlwB1C5vnYRkh3tQItJu3OR5EfbF1a3Skx9g6fhCFKbZyjNWZbVxmfn9GDYmeviJiVsp2c0Wf5qg7QT5MJZtzHFB4T+/fV9TQetBCW9LKctFclCjgrw0aaqxNUHaDBvsR/uOG7KchmsuZa7DXvCc4vo15ZSVrCD5kGYhv+PzRfT4ht8r8S/GxAaPi8gZZsQBl/iOEAdhnWwTYwyZvxgkWegQw+guYfdZzi8JZmcoFA/OTognIG2SHMBu5nM8RpBfP8MKjP7UatbGPRo5+lNx26nxiw84bLVFokSxf5JcwhMP4CTHtR7tp6jnOaVHM3ANZ/Pk9mDuo9UBoLKt6amieTK+X9fvszpLbKpp9GKlp8bb4mk96Tgs1YP4108X1fMOJNrawn67OGXhJ+MqpiPs0ORDi5ILTCdfsxb+DLuAAyp/fcWuPnZEdC/VGFL/3Ydj9yqLuk3JFvwpSVD8nI+gZdFYI/qpRV4Q5mWoqzEyzObSj4yt8Do1FL1xgDEvdSxOqmLOB9Mer1DLzzTaE3O1Is3yvPerXJN7gqgpQ69k7if1a6H23AAeEVknNj6rQof2rBrFvnkquf/4uq01jVpQqW6Pez70eYPOuLyVRrdg/X8fSrXHiWdS/df9J0jRjFleHqJy9OI7MMyUK0OTfg1ZxBc8aSEkYaZ/u5G8BKJvhhySgiQvf+j4oAuPibIvZQZ3NF90Bso9hYL8HsvPB2CiYrNzTBuIafLJ6GfHT0dxamSSzP6rW+x+LnbUersORYhx65WekmTQM1Nh8+rFRTgKLQZAS9nVnc9GZ/aZ0SIN5+wWCAFwmLcpReuEcfFBKfdnItS8426wuRKIxzC9YkrQnTQkVuOpc/IUAFoVxApqMIWZYmFFpFGm5MWUiUYlq/Pb2rEgRyYhlASYxjL4QqERC2Aq1Fi8LOQ/TfTbkqyWZQqpWVWurlnMYCf5q8B1k21JwsCYbk/waosnRvbysiCJxzk4XbQ6vBrWiDurLh1KCGeFz8XFmhoudbdAjPWyB6TgY3K9OEHmVeHRbpCosy0gCuac5N6HGAqK9H1UpqgVGOqiSFC/EyRDUSXg14d8w7CZvZEsuMgPz29LGgGx0u2pLsWTsC5XHzgqT8vfJqFHm8w+0+rf9CO70eNcrkzVqn0ubtYDPHcTzdw8=",
    // Windows 10 technical preview
    L"BwIAAACkAABSU0EyAAgAAAEAAQA5WQn9lTT4Ci679UcfZW6y8GkbeGTN9bKbgjnigtWmb7pPkifbr3ihmmtJ1ZWJmZCyDyeRNHwHDieOiM8zfgRJr575RKQI8yWi6wNAZVhUZDzKlch4BgABut2lcjZRT5o/Iyotd0tKW7Np1ur8D/HawdmHXdhN42hjg7PKNfvbgXICNNK+uschVzA39HWejEowO5ppaXBObLpN28Ipun3+s0xPNePHNVKD/4azFGd11ZZWmoh3NpnZXBGW3Jk2fn6hmrQ434Mrw4qdpIfTqh/d0aWGE7CseZPYR0F9Gd6DWyXn6JzkvPBPRNtdU7SK5Xeh+pDmTnme5av3c1XNBka2hScgqAT/BOAwaIvufA6QZXccHkeHnOVO/XHEi339OT0FJLNWearerYzfHtHh6D8+d7fIdHBsgMCMd/O2suhNVBWsipzA8UPnhy4+4uPAhoV7fqaYjPbE0fUTXT82SUG11W4tjs8+kTflzwX1qoNezfLdG6++h7LJSGJNPe2QfsQlB8NxLTReIHsyW5Fv5Q0LZH/Z5tJsOeu0P39z9k/oW30TGHIVnipOkdfA1PREFFwDWJ7MKsTQkW2ikSo9Y1HbUhIAb2xI9M28GAxGxdaPa69vAepfqiPOfEFOiZcUhVkLs6vv8GVOsLRMHFalKhwNi6bWX32R76OKmRHLPPl47dkHCBy/nBVSLaVyUo25gEX3pVgGDpoiHOTzeq1qvPdguBMXHtgvpvEMTBEMDFpp1hMqWkNcapPA25oGQmJr5LouRsfaHXe52LoJpniCA/Lf7cFSCbx+Wkh1bl/4uepz45bZGpjde4WvPnKPBOsi+EZ30lYi0mfKGBQ7HS6RE9iQSbOJYZ2djnY+ok8VkGrXU28l1kQParu3mnXOcQdviIJhtH6nor3GjXYbMml40/b3lGPn6qPjf0UW9glD2apdQMyTTxO2YzLlpiW96d5SwsPTDfP83YTZUZd6Er4cvmlb7G4qidlF7xIdVzzmGx5PPAuv6oLzMf3qFHKgo8nGC3ZcHfTsHz62eTvDFfCxuqTSbZYby+SraGvez3gZSKnbmvkfaBumgMPULGjsPC0FGMf1PXzxHQ3Y5chnpxYXF86h9NRRf9efeByhj3cS1AQGNidgIfo1l0CdNDtWegcZC/0U8+0O/lMGUnemt8a+Zl6jb+XHB9czxWjfetE3KcLXlfXrIBMM7Ve3JNEU1dL01vZ7THJXYWS6mIvGnOK+nW4GxsgReW8an5HlE1qF3O0r0vmpttZ6tK0NjxZFrUIVJwE+X/rJrRIS7eJJsgLoI4HD37AMcQ3rGY4/mnR7JitqNj4TNq+P/XNNl7wkjmRLOruLrOdShKON1ZvmaZ9BKUYI02FjxRntO8MPOrR2ImdRpTp+1rGtLlWWe0MxmPOkIQIsPKocIeitjWXIgNErcdzulagizd+cmcf2PPOyNkOd7yVv1xxxLy2ePYsHdGaYxIgM0xJ+NNrNpLz9/3W2quhEt4JL6jIhnIuvIUd67SQLwf7qy2jS3lLwbkBqPJpalAE=",
    // End of data
    NULL
};

BOOL set_rsa_crypto_key(WIM_INFO *esd, const WCHAR *base64_crypto_key, int key_index)
{
    DWORD crypto_key_size = sizeof(esd->crypto_key);

    if ( !CryptStringToBinaryW(base64_crypto_key, 0, CRYPT_STRING_BASE64, (BYTE *)&esd->crypto_key, &crypto_key_size, NULL, NULL) )
    {
        fwprintf(stderr, L"ERROR: Error while base64 decoding CryptoKey #%d.\n", key_index);
        return FALSE;
    }

    return TRUE;
}

BOOL open_input_file(WIM_INFO *esd, const WCHAR *esd_path)
{
    int ret = _wfopen_s(&esd->wim_file, esd_path, L"r+b");

    if ( ret != 0 )
    {
        fwprintf(stderr, L"ERROR: Cannot open input ESD image.\n");
        return FALSE;
    }

    return TRUE;
}

BOOL check_wim_header(WIM_INFO *esd)
{
    _fseeki64(esd->wim_file, 0, SEEK_SET);

    if ( fread(&esd->hdr, WIM_HEADER_SIZE, 1, esd->wim_file) < 1 )
    {
        fwprintf(stderr, L"ERROR: Cannot read WIM header from the ESD image.\n");
        return FALSE;
    }

    if ( esd->hdr.wim_tag != WIM_TAG ||
        esd->hdr.hdr_size != WIM_HEADER_SIZE ||
        esd->hdr.wim_version != ESD_IMAGE_VERSION ||
        esd->hdr.wim_flags != ESD_IMAGE_FLAGS )
    {
        fwprintf(stderr, L"ERROR: The ESD file is not a valid encrypted image.\n");
        return FALSE;
    }

    return TRUE;
}

BOOL get_xml_data(WIM_INFO *esd)
{
    esd->xml.offset = esd->hdr.xml_data.offset_in_wim;
    esd->xml.size = esd->hdr.xml_data.size_in_wim;

    WCHAR *xml_data = (WCHAR *)malloc((size_t)esd->xml.size + 2);

    _fseeki64(esd->wim_file, esd->xml.offset, SEEK_SET);

    if ( fread(xml_data, (size_t)esd->xml.size, 1, esd->wim_file) < 1 )
    {
        free(xml_data);
        fwprintf(stderr, L"ERROR: Cannot read embedded XML data from ESD image.\n");
        return FALSE;
    }

    xml_data[esd->xml.size >> 1] = 0;
    esd->xml.data = xml_data;

    return TRUE;
}

WCHAR *find_esd_tag(WCHAR *xml_data)
{
    WCHAR *esd_tag = wcsstr(xml_data, L"<ESD>");

    if ( esd_tag == NULL || esd_tag == xml_data )
    {
        fwprintf(stderr, L"ERROR: Cannot find <ESD> tag within the embedded XML data.\n");
        return NULL;
    }

    return esd_tag;
}

BOOL decode_session_key(WCHAR *esd_data, SIMPLEKEYBLOB *session_key)
{
    WCHAR *key_start = wcsstr(esd_data, L"<KEY>");
    WCHAR *key_end = wcsstr(esd_data, L"</KEY>");

    if ( key_start == NULL || key_end == NULL )
    {
        fwprintf(stderr, L"ERROR: Cannot find <KEY> tag within the embedded XML data.\n");
        return FALSE;
    }

    WCHAR *base64_session_key = key_start + 5;
    DWORD key_length = key_end - base64_session_key;
    DWORD key_size = sizeof(session_key->key);

    if ( !CryptStringToBinaryW(base64_session_key, key_length, CRYPT_STRING_BASE64, (BYTE *)&session_key->key, &key_size, NULL, NULL) )
    {
        fwprintf(stderr, L"ERROR: Error while base64 decoding session key.\n");
        return FALSE;
    }

    for ( int i = 0; i < _countof(session_key->key) >> 1; i++ )
        SWAP(BYTE, session_key->key[_countof(session_key->key) - i - 1], session_key->key[i]);

    session_key->hdr.bType = SIMPLEBLOB;
    session_key->hdr.bVersion = CUR_BLOB_VERSION;
    session_key->hdr.reserved = 0;
    session_key->hdr.aiKeyAlg = CALG_AES_256;
    session_key->algid = CALG_RSA_KEYX;

    return TRUE;
}

BOOL get_encrypted_ranges(WCHAR *esd_data, WIM_INFO *esd) 
{
    WCHAR *encrypted_tag = wcsstr(esd_data, L"<ENCRYPTED Count=\"");

    if ( encrypted_tag == NULL )
    {
        fwprintf(stderr, L"ERROR: Cannot find <ENCRYPTED> tag in the embedded XML.\n");
        return FALSE;
    }

    if ( swscanf_s(encrypted_tag, L"<ENCRYPTED Count=\"%d\">", &esd->num_encrypted_ranges) != 1 )
    {
        fwprintf(stderr, L"ERROR: Cannot get the count of encrypted ranges.\n");
        return FALSE;
    }

    esd->encrypted_ranges = (RANGE_INFO *)malloc(esd->num_encrypted_ranges * sizeof(RANGE_INFO));

    WCHAR *range_tag = wcsstr(encrypted_tag, L"<RANGE Offset=\"");
    BOOL success = TRUE;

    for ( int i = 0; i < esd->num_encrypted_ranges; i++ )
    {
        if ( range_tag == NULL ||
            swscanf_s(range_tag, L"<RANGE Offset=\"%I64d\" Bytes=\"%d\">", &esd->encrypted_ranges[i].offset, &esd->encrypted_ranges[i].bytes) != 2 )
        {
            fwprintf(stderr, L"ERROR: Cannot get the encrypted range info.\n");
            success = FALSE;
            break;
        }

        range_tag = wcsstr(++range_tag, L"<RANGE Offset=\"");
    }

    return success;
}

BOOL read_embedded_xml(WIM_INFO *esd)
{
    if ( !get_xml_data(esd) )
        return FALSE;

    WCHAR *esd_data = find_esd_tag(esd->xml.data);

    if ( esd_data == NULL || !decode_session_key(esd_data, &esd->session_key) )
        return FALSE;

    if ( !get_encrypted_ranges(esd_data, esd) )
        return FALSE;

    return TRUE;
}

BOOL decrypt_blocks(WIM_INFO *esd)
{
    HCRYPTPROV hProv = NULL;
    HCRYPTKEY hPubKey = NULL;
    HCRYPTKEY hKey = NULL;
    BOOL success = TRUE;

    if ( !CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) ||
        !CryptImportKey(hProv, (BYTE *)&esd->crypto_key, sizeof(esd->crypto_key), 0, CRYPT_EXPORTABLE | CRYPT_OAEP, &hPubKey) ||
        !CryptImportKey(hProv, (BYTE *)&esd->session_key, sizeof(esd->session_key), hPubKey, CRYPT_EXPORTABLE | CRYPT_OAEP, &hKey) )
    {
        success = FALSE;
        goto fail;
    }

    for ( int i = 0; i < esd->num_encrypted_ranges; i++ )
    {
        int blocks = esd->encrypted_ranges[i].bytes >> 4;
        DWORD size = (blocks + 1) << 4;
        BYTE *data = (BYTE *)calloc(size, 1);

        _fseeki64(esd->wim_file, esd->encrypted_ranges[i].offset, SEEK_SET);
        fread(data, esd->encrypted_ranges[i].bytes, 1, esd->wim_file);
        CryptDecrypt(hKey, NULL, TRUE, 0, data, &size);

        _fseeki64(esd->wim_file, esd->encrypted_ranges[i].offset, SEEK_SET);

        fwrite(data, 16, blocks, esd->wim_file);
        fflush(esd->wim_file);

        free(data);
    }

fail:
    if ( hPubKey != NULL )
        CryptDestroyKey(hPubKey);
    if ( hKey != NULL )
        CryptDestroyKey(hKey);
    if ( hProv != NULL )
        CryptReleaseContext(hProv, 0);

    return success;
}

BOOL update_integrity_info(WIM_INFO *esd, WIM_HASH_TABLE **updated_table)
{
    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;
    BOOL success = TRUE;

    if ( !CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) ||
        !CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash) )
    {
        fwprintf(stderr, L"ERROR: Error while creating hash objects.\n");
        success = FALSE;
        goto fail;
    }

    WIM_HASH_TABLE *hash_table = (WIM_HASH_TABLE *)malloc(esd->hdr.integrity_table.size_in_wim);

    _fseeki64(esd->wim_file, esd->hdr.integrity_table.offset_in_wim, SEEK_SET);
    fread(hash_table, esd->hdr.integrity_table.size_in_wim, 1, esd->wim_file);

    ULONGLONG size_hashed = esd->hdr.lookup_table.offset_in_wim + esd->hdr.lookup_table.size_in_wim - WIM_HEADER_SIZE;
    DWORD chunk_size = hash_table->chunk_size;
    BYTE *data = (BYTE *)malloc(hash_table->chunk_size);
    DWORD bytes_read;

    for ( int i = 0; i < esd->num_encrypted_ranges; i++ )
    {
        int block_start = (int)(esd->encrypted_ranges[i].offset / chunk_size);
        int block_end = (int)((esd->encrypted_ranges[i].offset + esd->encrypted_ranges[i].bytes) / chunk_size);

        _fseeki64(esd->wim_file, block_start * chunk_size + WIM_HEADER_SIZE, SEEK_SET);

        for ( int j = block_start; j <= block_end; j++ )
        {
            if ( j == (int)(hash_table->num_elements - 1) )
                bytes_read = (DWORD)(size_hashed - (hash_table->num_elements - 1) * chunk_size);
            else
                bytes_read = chunk_size;

            fread(data, bytes_read, 1, esd->wim_file);

            HCRYPTHASH hHashDup;
            DWORD hash_size = SHA1_HASH_SIZE;
            
            CryptDuplicateHash(hHash, 0, 0, &hHashDup);
            CryptHashData(hHashDup, data, bytes_read, 0);
            CryptGetHashParam(hHashDup, HP_HASHVAL, hash_table->hash_list[j], &hash_size, 0);
            CryptDestroyHash(hHashDup);
        }
    }

    free(data);
    *updated_table = hash_table;

fail:
    if ( hHash != NULL )
        CryptDestroyHash(hHash);
    if ( hProv != NULL )
        CryptReleaseContext(hProv, 0);

    return success;
}

BOOL update_xml_info(WIM_INFO *esd, ULONGLONG *wim_total_bytes)
{
    const WCHAR wim_tag_end[] = { L"\r\n</WIM>" };
    WCHAR *esd_tag_start = find_esd_tag(esd->xml.data);

    memcpy(esd_tag_start, wim_tag_end, sizeof(wim_tag_end));
    esd->xml.size = wcslen(esd->xml.data) << 1;

    ULONGLONG total_bytes = esd->xml.offset + esd->xml.size + esd->hdr.integrity_table.size_in_wim;
    WCHAR new_size_string[16];
    _ui64tow_s(total_bytes, new_size_string, _countof(new_size_string), 10);

    WCHAR *first_total_bytes_tag = wcsstr(esd->xml.data, L"<TOTALBYTES>");
    memcpy(first_total_bytes_tag + 12, new_size_string, wcslen(new_size_string) << 1);

    *wim_total_bytes = total_bytes;

    return TRUE;
}

BOOL update_wim_info(WIM_INFO *esd)
{
    WIM_HASH_TABLE *new_integrity_table = NULL;
    ULONGLONG total_bytes;
    BOOL success = TRUE;

    if ( !update_integrity_info(esd, &new_integrity_table) ||
        !update_xml_info(esd, &total_bytes) )
    {
        success = FALSE;
        goto fail;
    }

    esd->hdr.xml_data.size_in_wim = esd->hdr.xml_data.original_size = esd->xml.size;
    _fseeki64(esd->wim_file, esd->xml.offset, SEEK_SET);
    fwrite(esd->xml.data, (size_t)esd->xml.size, 1, esd->wim_file);

    esd->hdr.integrity_table.offset_in_wim = _ftelli64(esd->wim_file);
    fwrite(new_integrity_table, new_integrity_table->size, 1, esd->wim_file);
    fflush(esd->wim_file);
    free(new_integrity_table);

    _fseeki64(esd->wim_file, 0, SEEK_SET);
    fwrite(&esd->hdr, WIM_HEADER_SIZE, 1, esd->wim_file);
    fflush(esd->wim_file);

    int fd = _fileno(esd->wim_file);
    _chsize_s(fd, total_bytes);

fail:
    return success;
}

void cleanup_resources(WIM_INFO *esd)
{
    if ( esd->wim_file != NULL )
        fclose(esd->wim_file);

    if ( esd->xml.data != NULL )
        free(esd->xml.data);

    if ( esd->encrypted_ranges != NULL )
        free(esd->encrypted_ranges);
}

int wmain(int argc, WCHAR *argv[])
{
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

    WIM_INFO esd;
    memset(&esd, 0, sizeof(esd));

    _wsetlocale(LC_ALL, L"");

    if ( argc < 2 || argc > 3 )
    {
        fwprintf(stderr, L"Usage: esddecrypt <encrypted esd> <base64 cryptokey>\n");
        fwprintf(stderr, L"       *** Warning ***\n");
        fwprintf(stderr, L"       The input will be directly OVERWRITTEN by the decrypted image!\n");
        return ERROR_INVALID_PARAMETER;
    }

    if ( argc == 3 )
    {
        known_base64_crypto_keys[0] = argv[2];
        known_base64_crypto_keys[1] = NULL;
    }

    BOOL success = TRUE;

    if (
        !open_input_file(&esd, argv[1]) ||
        !check_wim_header(&esd) ||
        !read_embedded_xml(&esd)
        )
    {
        success = FALSE;
        goto cleanup;
    }

    BOOL decryption_success = FALSE;

    for ( int i=0; known_base64_crypto_keys[i]; i++ )
    {
        if (
            !set_rsa_crypto_key(&esd, known_base64_crypto_keys[i], i) ||
            !decrypt_blocks(&esd)
            )
        {
            continue;
        }
        else
        {
            decryption_success = TRUE;
        }
    }

    if ( decryption_success )
        update_wim_info(&esd);
    else
    {
        fwprintf(stderr, L"ERROR: Decryption failed. None of the known/specified RSA key works.\n");
        success = FALSE;
    }

cleanup:
    cleanup_resources(&esd);
    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
