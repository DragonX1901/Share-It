import type {
    IExecuteFunctions,
    INodeExecutionData,
    INodeType,
    INodeTypeDescription,
} from 'n8n-workflow';
import { NodeConnectionTypes, NodeOperationError } from 'n8n-workflow';
import * as crypto from 'crypto';

export class SecretShare implements INodeType {
    description: INodeTypeDescription = {
        displayName: 'SecretShare',
        name: 'secretShare',
        icon: { light: 'file:lock.svg', dark: 'file:lock.dark.svg' },
        group: ['transform'],
        version: 1,
        description: 'Encrypt and decrypt secrets for sharing',
        defaults: {
            name: 'SecretShare',
        },
        usableAsTool: true,
        inputs: [NodeConnectionTypes.Main],
        outputs: [NodeConnectionTypes.Main],
        properties: [
            {
                displayName: 'Operation',
                name: 'operation',
                type: 'options',
                noDataExpression: true,
                options: [
                    { name: 'Encrypt', value: 'encrypt' },
                    { name: 'Decrypt', value: 'decrypt' },
                ],
                default: 'encrypt',
                description: 'Whether to encrypt or decrypt the provided value',
            },
            {
                displayName: 'Secret',
                name: 'secret',
                type: 'string',
                typeOptions: {
                    password: true,
                },
                default: '',
                displayOptions: {
                    show: {
                        operation: ['encrypt'],
                    },
                },
                placeholder: 'The secret to encrypt (API key, password, etc.)',
            },
            {
                displayName: 'Encrypted',
                name: 'encrypted',
                type: 'string',
                default: '',
                displayOptions: {
                    show: {
                        operation: ['decrypt'],
                    },
                },
                placeholder: 'Base64 encrypted payload',
            },
            {
                displayName: 'Passphrase',
                name: 'passphrase',
                type: 'string',
                typeOptions: {
                    password: true,
                },
                default: '',
                description: 'A passphrase used to derive the encryption key',
            },
        ],
    };

    // Helper: derive 32-byte key from passphrase
    private deriveKey(passphrase: string): Buffer {
        return crypto.createHash('sha256').update(passphrase, 'utf8').digest();
    }

    // Encrypt plaintext -> base64(iv|authTag|ciphertext)
    private encryptString(plain: string, passphrase: string): string {
        const key = this.deriveKey(passphrase);
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const ciphertext = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
        const authTag = cipher.getAuthTag();
        return Buffer.concat([iv, authTag, ciphertext]).toString('base64');
    }

    // Decrypt base64(iv|authTag|ciphertext) -> plaintext
    private decryptString(payloadB64: string, passphrase: string): string {
        const key = this.deriveKey(passphrase);
        const data = Buffer.from(payloadB64, 'base64');
        if (data.length < 12 + 16) {
            throw new NodeOperationError(this.getNode(), new Error('Invalid payload'));
        }
        const iv = data.slice(0, 12);
        const authTag = data.slice(12, 28);
        const ciphertext = data.slice(28);
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(authTag);
        const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        return decrypted.toString('utf8');
    }

    async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
        const items = this.getInputData();

        for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
            try {
                const operation = this.getNodeParameter('operation', itemIndex) as string;
                const passphrase = (this.getNodeParameter('passphrase', itemIndex, '') as string) || '';

                if (!passphrase) {
                    throw new NodeOperationError(this.getNode(), 'Passphrase is required', { itemIndex });
                }

                if (operation === 'encrypt') {
                    const secret = this.getNodeParameter('secret', itemIndex, '') as string;
                    const encrypted = this.encryptString(secret, passphrase);
                    items[itemIndex].json.encrypted = encrypted;
                } else {
                    const encrypted = this.getNodeParameter('encrypted', itemIndex, '') as string;
                    const decrypted = this.decryptString(encrypted, passphrase);
                    items[itemIndex].json.decrypted = decrypted;
                }
            } catch (error) {
                if (this.continueOnFail()) {
                    items[itemIndex].json = { error: (error as Error).message };
                    continue;
                }
                if (error instanceof Error && (error as NodeOperationError).context) {
                    (error as NodeOperationError).context.itemIndex = itemIndex;
                    throw error;
                }
                throw new NodeOperationError(this.getNode(), error as Error, { itemIndex });
            }
        }

        return [items];
    }
}
