import time
import secrets
import PySimpleGUI as sg
import pyaes


class AES:
    key_size_of_aes = {16: 10, 24: 12, 32: 14}

    def __init__(self, key, iv):
        assert len(key) in AES.key_size_of_aes
        self.iv = [iv[i] for i in range(len(iv))]
        self.aes = pyaes.AES(key)

    def increase_bytes(self, nonce):
        inc = nonce

        for i in range(len(nonce) - 1, 0, -1):
            if inc[i] == 0xFF:
                inc[i] = 0
            else:
                inc[i] += 1
                break
        return nonce

    def xor_bytes(self, a, b):
        if len(a) > len(b):
            return [(x ^ y) for (x, y) in zip(a[:len(b)], b)]
        else:
            return [(x ^ y) for (x, y) in zip(a, b[:len(a)])]

    def add_pad_PKCS(self, text):
        padding_len = 16 - (len(text) % 16)
        for i in range(padding_len):
            text += [padding_len]
        return text

    def remove_pad_PKCS(self, text):
        padding_len = text[-1]
        assert padding_len > 0
        message, padding = text[:-padding_len], text[-padding_len:]
        return message

    def split_16bytes(self, message):
        assert len(message) % 16 == 0
        message_16bytes = [message[i:i + 16] for i in range(0, len(message), 16)]
        return message_16bytes

    def split_bytes(self, message):
        message_bytes = []
        for i in range(0, len(message), 16):
            if i < len(message):
                message_bytes.append(message[i:i + 16])
            else:
                message_bytes.append(message[i:len(message) - i + 16])
        return message_bytes

    # ECB mode
    def ecb_encrypt(self, plaintext):
        plaintext = [bytetext for bytetext in plaintext]
        plaintext = self.add_pad_PKCS(plaintext)
        blocks = []

        for text_in_block_bytes in self.split_16bytes(plaintext):
            block = self.aes.encrypt(text_in_block_bytes)
            blocks.extend(block)

        return bytes(block for block in blocks)

    def ecb_decrypt(self, plaintext):
        plaintext = [bytetext for bytetext in plaintext]
        blocks = []

        for text_in_block_bytes in self.split_16bytes(plaintext):
            block = self.aes.decrypt(text_in_block_bytes)
            blocks.extend(block)

        blocks = self.remove_pad_PKCS(blocks)
        return bytes(block for block in blocks)

    # CBC mode
    def cbc_encrypt(self, plaintext):
        iv = self.iv
        plaintext = [bytetext for bytetext in plaintext]
        plaintext = self.add_pad_PKCS(plaintext)

        blocks = []
        previous = iv.copy()
        block = self.aes.encrypt(iv.copy())
        blocks.extend(block)

        for text_in_block_bytes in self.split_16bytes(plaintext):
            block = self.aes.encrypt(self.xor_bytes(text_in_block_bytes, previous))
            blocks.extend(block)
            previous = block

        return bytes(block for block in blocks)

    def cbc_decrypt(self, ciphertext):
        iv = [bytetext for bytetext in ciphertext][:16]
        iv = self.aes.decrypt(iv)
        ciphertext = [bytetext for bytetext in ciphertext][16:]

        blocks = []
        previous = iv.copy()

        for cipher_block in self.split_16bytes(ciphertext):
            block = self.xor_bytes(previous, self.aes.decrypt(cipher_block))
            blocks.extend(block)
            previous = cipher_block

        blocks = self.remove_pad_PKCS(blocks)
        return bytes(block for block in blocks)

    # CTR mode
    def ctr_encrypt(self, plaintext, start_nonce=None, start_blocks=None):
        iv = self.iv
        if start_nonce is None:
            nonce = iv.copy()
        else:
            nonce = start_nonce.copy()

        if start_blocks is None:
            blocks = []
        else:
            blocks = start_blocks.copy()

        plaintext = [bytetext for bytetext in plaintext]

        block = self.aes.encrypt(iv.copy())
        blocks.extend(block)

        for text_to_block_bytes in self.split_bytes(plaintext):
            block = self.xor_bytes(text_to_block_bytes, self.aes.encrypt(nonce))
            blocks.extend(block)
            nonce = self.increase_bytes(nonce)

        return bytes(block for block in blocks)

    def ctr_decrypt(self, ciphertext):
        iv = [bytetext for bytetext in ciphertext][:16]
        iv = self.aes.decrypt(iv)
        ciphertext = [bytetext for bytetext in ciphertext][16:]
        blocks = []
        nonce = iv.copy()

        for text_to_block_bytes in self.split_bytes(ciphertext):
            block = self.xor_bytes(text_to_block_bytes, self.aes.encrypt(nonce))
            blocks.extend(block)
            nonce = self.increase_bytes(nonce)

        return bytes(block for block in blocks)

    # CCM mode
    def ccm_cbc_mac(self, plaintext):
        iv = [0] * 16
        plaintext = [bytetext for bytetext in plaintext]
        plaintext = self.add_pad_PKCS(plaintext)

        cbc_mac_calculate = iv.copy()

        for text_in_block_bytes in self.split_16bytes(plaintext):
            block = self.aes.encrypt(self.xor_bytes(text_in_block_bytes, cbc_mac_calculate))
            cbc_mac_calculate = block

        return cbc_mac_calculate

    def ccm_encrypt(self, plaintext):
        iv = self.iv
        blocks = []
        nonce = iv.copy()
        plaintext = [bytetext for bytetext in plaintext]

        mac = self.ccm_cbc_mac(plaintext)

        block = self.xor_bytes(self.aes.encrypt(nonce), mac)
        blocks.extend(block)
        nonce = self.increase_bytes(nonce)

        return self.ctr_encrypt(plaintext, nonce, blocks)

    def ccm_decrypt(self, ciphertext):
        ciphertext = [bytetext for bytetext in ciphertext]
        iv = [bytetext for bytetext in ciphertext][16:32]
        iv = self.aes.decrypt(iv)
        nonce = iv.copy()

        mac = self.xor_bytes([bytetext for bytetext in ciphertext][:16], self.aes.encrypt(iv.copy()))
        nonce = self.increase_bytes(nonce)

        blocks = []
        ciphertext = [bytetext for bytetext in ciphertext][32:]

        for text_to_block_bytes in self.split_bytes(ciphertext):
            block = self.xor_bytes(text_to_block_bytes, self.aes.encrypt(nonce))
            blocks.extend(block)
            nonce = self.increase_bytes(nonce)

        verify_mac = self.ccm_cbc_mac(blocks)

        print("------>> Is authenticated MAC? ", verify_mac == mac)

        return bytes(block for block in blocks)


def start_gui():
    layout = [
        [sg.Text('Šifriranje'), sg.InputText(), sg.FileBrowse('Odpri')],
        [sg.Text('Dešifriranje'), sg.InputText(), sg.FileBrowse('Odpri')],
        [sg.Text('Način šifriranja'),
         sg.Radio("ECB", "CipherMode", default=True),
         sg.Radio("CBC", "CipherMode", default=False),
         sg.Radio("CTR", "CipherMode", default=False),
         sg.Radio("CCM", "CipherMode", default=False)
         ],
        [sg.Output(size=(88, 20))],
        [sg.Button(button_text='Šifriraj'), sg.Button(button_text='Dešifriraj'), sg.Cancel(button_text='Zapri')]
    ]
    window = sg.Window('AES', layout)

    while True:
        event, values = window.read()
        if event in (None, 'Exit', 'Cancel', 'Zapri'):
            break
        if event == 'Submit' or event == 'Šifriraj' or event == 'Dešifriraj':
            filepath = key = is_validation_ok = None
            if values[0] or values[1]:
                if event == 'Šifriraj':
                    filepath = values[0]
                elif event == 'Dešifriraj':
                    filepath = values[1]

                is_validation_ok = True
                if not filepath and filepath is not None:
                    print('Napaka: pot do datoteke ni pravilna.')
                    is_validation_ok = False
                elif is_validation_ok:
                    try:
                        start_time = time.process_time()
                        with open(filepath, 'rb') as data:

                            raw_data = data.read()
                            print(f"--- Open and read FILE Time --- {time.process_time() - start_time}")

                            if event == 'Šifriraj':
                                key = secrets.token_bytes(16)
                                iv = secrets.token_bytes(16)

                                with open(filepath[:-len(filepath.split("/")[-1])] + "secret_key.txt",
                                          'wb') as secret_keys:
                                    secret_keys.write(key)

                                cipher = AES(key, iv)

                                start_time = time.process_time()

                                if values[2]:  # ECB
                                    encrypted_file = cipher.ecb_encrypt(raw_data)
                                elif values[3]:  # CBC
                                    encrypted_file = cipher.cbc_encrypt(raw_data)
                                elif values[4]:  # CTR
                                    encrypted_file = cipher.ctr_encrypt(raw_data)
                                elif values[5]:  # CCM
                                    encrypted_file = cipher.ccm_encrypt(raw_data)

                                print(f"--- encrypted_file Time --- {time.process_time() - start_time}")
                                print(
                                    f"--- encrypted_file cycles per second --- {(len(raw_data) / (time.process_time() - start_time)) * 10 ** -6} MB/s")

                                filepath = filepath[:-4] + '-result-encrypted' + filepath[-4:]
                                with open(filepath, 'wb') as encrypted_result:
                                    encrypted_result.write(encrypted_file)

                            if event == 'Dešifriraj':

                                with open(filepath[:-len(filepath.split("/")[-1])] + "secret_key.txt",
                                          'rb') as secret_keys:
                                    key = secret_keys.read()
                                iv = secrets.token_bytes(16)

                                cipher = AES(key, iv)

                                start_time = time.process_time()

                                if values[2]:  # ECB
                                    decrypted_file = cipher.ecb_decrypt(raw_data)
                                elif values[3]:  # CBC
                                    decrypted_file = cipher.cbc_decrypt(raw_data)
                                elif values[4]:  # CTR
                                    decrypted_file = cipher.ctr_decrypt(raw_data)
                                elif values[5]:  # CCM
                                    decrypted_file = cipher.ccm_decrypt(raw_data)

                                print(f"--- decrypted_file Time --- {time.process_time() - start_time}")
                                print(
                                    f"--- decrypted_file  cycles per second --- {(len(raw_data) / (time.process_time() - start_time)) * 10 ** -6} MB/s")

                                filepath = filepath[:-4].split("-result-encrypted")[0] + '-result-decrypted' + filepath[
                                                                                                               -4:]
                                with open(filepath, 'wb') as decrypted_result:
                                    decrypted_result.write(decrypted_file)

                            print('Pot datoteke:', filepath)
                            print('Ključ: ', key)
                            # print('IV: ', iv)
                            print("------------------------------------------------")
                    except:
                        print('*** Napaka v procesu šifriranja/dešifriranja ***')
            else:
                print('Napaka pri vnosnih poljih')
    window.close()


if __name__ == '__main__':
    start_gui()
