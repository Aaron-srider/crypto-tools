import request from '@/request';
import { AxiosPromise } from 'axios';

class Client {
    // region: Playground Project Template
    static createPlaygroundProjectTemplateFromDirectory(
        path: string,
        name: string,
    ): AxiosPromise<any> {
        return request({
            url: `/playground-project-template/from-directory`,
            method: 'post',
            data: {
                path,
                name,
            },
        });
    }
    static uploadPlaygroundProjectTemplate(
        formData: FormData,
    ): AxiosPromise<any> {
        return request({
            url: `/playground-project-template`,
            method: 'post',
            data: formData,
        });
    }
    static updatePlaygroundProjectTemplateBinary(
        playgroundProjectTemplateId: number,
        formData: FormData,
    ): AxiosPromise<any> {
        return request({
            url: `/playground-project-template-binary/${playgroundProjectTemplateId}`,
            method: 'put',
            data: formData,
        });
    }

    static deletePlaygroundProjectTemplate(
        playgroundProjectTemplateId: number,
    ): AxiosPromise<any> {
        return request({
            url: `/playground-project-template/${playgroundProjectTemplateId}`,
            method: 'delete',
        });
    }

    static getPlaygroundProjectTemplateList(): AxiosPromise<any> {
        return request({
            url: `/playground-project-templates`,
            method: 'get',
        });
    }

    static downloadPlaygroundProjectTemplate(
        playgroundProjectTemplateId: number,
    ): AxiosPromise<any> {
        return request({
            url: `/playground-project-template/${playgroundProjectTemplateId}`,
            method: 'get',
            params: { playgroundProjectTemplateId },
            responseType: 'blob',
        });
    }
    // endregion

    static getResult(userInput: string, userInputMode: string) {
        return request({
            url: `/bytes-format-translation`,
            method: 'get',
            params: {
                userInput,
                userInputMode
            }
        });
    }

    static cert(pubKeyInput: string) {
        return request({
            url: `/cert`,
            method: 'get',
            params: {
                pubKeyBase64: pubKeyInput
            }
        });
    }
}

export default Client;
