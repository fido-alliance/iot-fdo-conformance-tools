export const getDOTsList = async (): Promise<Array<any>> => {
    let result = await fetch("/api/dot/testruns", {
        method: "GET",
        headers: {
            "Content-Type": "application/json",
        },
    });

    let resultJson = await result.json();

    if (result.status !== 200) {
        let statusText = result.statusText;

        if (resultJson !== undefined && resultJson.errorMessage !== undefined) {
            statusText = resultJson.errorMessage;
        }

        return Promise.reject(`Error sending request: ${statusText}`);
    }

    return resultJson.entries;
};

export const addNewDo = async (url, privKey): Promise<Array<any>> => {
    let result = await fetch("/api/dot/create", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ url, priv_key: privKey }),
    });

    let resultJson = await result.json();

    if (result.status !== 200) {
        let statusText = result.statusText;

        if (resultJson !== undefined && resultJson.errorMessage !== undefined) {
            statusText = resultJson.errorMessage;
        }

        return Promise.reject(`Error sending request: ${statusText}`);
    }

    return resultJson.rvts;
};

export const executeDoTests = async (id): Promise<Array<any>> => {
    let result = await fetch("/api/dot/execute", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ id }),
    });

    let resultJson = await result.json();

    if (result.status !== 200) {
        let statusText = result.statusText;

        if (resultJson !== undefined && resultJson.errorMessage !== undefined) {
            statusText = resultJson.errorMessage;
        }

        return Promise.reject(`Error sending request: ${statusText}`);
    }

    return resultJson.rvts;
};

export const removeTestRun = async (
    id: string,
    testRunId: string
): Promise<Array<any>> => {
    let result = await fetch(`/api/dot/testruns/${id}/${testRunId}`, {
        method: "DELETE",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ id, testRunId }),
    });

    let resultJson = await result.json();

    if (result.status !== 200) {
        let statusText = result.statusText;

        if (resultJson !== undefined && resultJson.errorMessage !== undefined) {
            statusText = resultJson.errorMessage;
        }

        return Promise.reject(`Error sending request: ${statusText}`);
    }

    return resultJson.rvts;
};
