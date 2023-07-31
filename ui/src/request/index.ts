/**
 * This module will:
 *
 * 1. Create an initialized axios instance
 *
 * 2. Add request interceptor to log request info
 *
 * 3. Add response interceptor to handle some global response codes
 */
import axios from 'axios';
import {Message, Notification} from 'element-ui';
import { PageLocation } from '@/ts/dynamicLocation';
import globalHandledRespCodes, {
    SUCCESS,
} from '@/ts/GlobalHandledResponseCode';

// create an axios instance
const service = axios.create({
    baseURL: new PageLocation().baseURL, // url = base url + request url
    // withCredentials: true, // send cookies when cross-domain requests
    timeout: 5000, // request timeout
});

// request interceptor
service.interceptors.request.use(
    (config) => {
        let logtag = `Network Request: =====> ${config.url}\n`;
        console.log(logtag, config);
        return config;
    },
    (error) => {
        // do something with request error
        console.log(error); // for debug
        return Promise.reject(error);
    },
);

// response interceptor
service.interceptors.response.use(
    /**
     * If you want to get http information such as headers or status
     * Please return  response => response
     */

    /**
     * Determine the request status by custom code
     * Here is just an example
     * You can also judge the status by HTTP Status Code
     */
    (response) => {
        const httpResponseData = response.data;
        let relativeUrl = response.config.url!.substring(
            response.config.baseURL!.length,
        );
        let logtag = `Network Response: <==== ${relativeUrl}\n`;
        let contentType = response?.headers?.['content-type'];

        console.log(logtag, `content-type: ${contentType}`);
        console.log(logtag, response);

        if (contentType == null) {
            // give a chance to handle error by specific request "then" handler
            return Promise.reject(response);
        }
        if (httpResponseData?.constructor.name == 'Blob') {
            let b: Blob = httpResponseData;
            if (b.type === 'application/json') {
                // return error message, read json text
                // prepare to read something from blob
                let fr = new FileReader();
                fr.onload = function () {
                    try {
                        let responseData = JSON.parse(this.result as string);
                        Notification.success(responseData);
                    } catch (e) {
                        Notification.success(this.result);
                    }
                };
                fr.readAsText(b);
            } else if (b.type === 'application/octet-stream') {
                dealWithOctet(response);
            } else {
                // error
                Notification.error('APP ERROR');
            }
        }

        console.log(logtag, 'pass response to invoker');
        return Promise.resolve(response);
    },
    (error) => {
        let response = error.response;

        if (response == null) {
            Notification.error('Server unreachable');
            return Promise.reject();
        }
        let status = response.status;
        let data = response.data;
        if (data?.constructor.name == 'Blob') {
            let b: Blob = data;
            if (b.type === 'application/json') {
                // return error message, read json text
                // prepare to read something from blob
                let fr = new FileReader();
                fr.onload = function () {
                    let responseData = JSON.parse(this.result as string);
                    Notification.error(responseData);
                };
                fr.readAsText(b);
            } else if (b.type === 'application/octet-stream') {
                // return file blob, download it
                // get file name from headers
                let responseHeaders = response.headers;
                let temp: string[] | undefined = (
                    responseHeaders['content-disposition'] as string | undefined
                )?.split('filename=');

                if (temp == undefined) {
                    Notification.error('No filename in response headers');
                    return;
                }

                let filename: string = temp[1];

                try {
                    filename = b64DecodeUnicode(filename);
                } catch (e) {
                    console.debug('filename doest need to base64 decode');
                }

                // create file link in browser's memory
                const href = URL.createObjectURL(response.data);

                // create "a" HTML element with href to file & click
                const link = document.createElement('a');
                link.href = href;
                link.setAttribute('download', filename); // or any other extension
                document.body.appendChild(link);
                link.click();

                // clean up "a" element & remove ObjectURL
                document.body.removeChild(link);
                URL.revokeObjectURL(href);
            } else {
                // error
                Notification.error('APP ERROR');
            }
        } else {
            Notification.error(`${status}: ${data}`);
        }
        return Promise.reject();
    },
);

function dealWithOctet(response) {
    // return file blob, download it
    // get file name from headers
    let responseHeaders = response.headers;
    let temp: string[] | undefined = (
        responseHeaders['content-disposition'] as string | undefined
    )?.split('filename=');

    if (temp == undefined) {
        Notification.error('No file name in response headers');
        return;
    }

    let filename: string = temp[1];

    try {
        filename = b64DecodeUnicode(filename);
    } catch (e) {
        console.debug('filename doest need to base64 decode');
    }

    // create file link in browser's memory
    const href = URL.createObjectURL(response.data);

    // create "a" HTML element with href to file & click
    const link = document.createElement('a');
    link.href = href;
    link.setAttribute('download', filename); // or any other extension
    document.body.appendChild(link);
    link.click();

    // clean up "a" element & remove ObjectURL
    document.body.removeChild(link);
    URL.revokeObjectURL(href);
}

function b64DecodeUnicode(str: string) {
    // Going backwards: from bytestream, to percent-encoding, to original string.
    return decodeURIComponent(
        atob(str)
            .split('')
            .map(function (c) {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            })
            .join(''),
    );
}
export default service;
