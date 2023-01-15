<script lang="ts">
    import svelteLogo from '../assets/FIDO_Alliance_logo_black_RGB.webp'
    import {login, isLoggedIn, getConfig, loginOnprem, getGithubRedirectUrl} from '../lib/User.api'
    import {push} from "svelte-spa-router"

    let email: string = ""
    let password: string = ""
    let errorMsg: string = ""
    let mode: string = ""

    const handleLogin = async (e) => {
        e.preventDefault()
        errorMsg = ""
        
        let prom = undefined
        if (mode == "online") {
            prom = login(email, password)
        } else {
            prom = loginOnprem()
        }
        
        await prom
        .then(() => {
            errorMsg = "Successfully logged in"
            window.setTimeout(() => push("/test"), 1000)
        })
        .catch((err) => {
            errorMsg = err
        })
    }

    const handleGithubLogin = async (e) => {
        e.preventDefault()
        errorMsg = "" 
        
        let prom = undefined
        if (mode == "online") {
            prom = getGithubRedirectUrl()
        } else {
            errorMsg = "This is only for Online mode"
            return
        }
        
        await prom
        .then((result) => {
            window.location.href = result;
        })
        .catch((err) => {
            errorMsg = err
        })
    }


    isLoggedIn()
    .then(async (isActually) => {
        const cfg = await getConfig()
        mode = cfg.mode;

        if (isActually) {
            if (mode === "onprem") {
                push("/test")
            } else {
                push("/menu")
            }
        }
    })
    
</script>

<style>
    .fidologo {
        border: none;
        border-radius: 0% !important;
    }
</style>

<section id="intro" class="main">
    <div class="spotlight">
        <div class="content">
            <header class="major">
                <h2>Login</h2>
            </header>

            <form method="post" action="#">
                <div class="row gtr-uniform">
                    {#if mode === "online"}
                        <div class="col-6 col-12-xsmall">
                            <input class="login_input" bind:value={email} type="text" placeholder="Email">
                        </div>
                        <div class="col-6 col-12-xsmall">
                            <input class="login_input" bind:value={password} type="password" placeholder="Password">
                        </div>
                    {/if}
                    
                    <div class="col-12">
                        <ul class="actions">
                            <li><input type="submit" on:click={handleLogin} value="Login" class="primary" /></li>
                        </ul>
                    </div>

                    <div class="col-12">
                        <ul class="actions">
                            <li><a href="/#/" style="color:#ffffffcc !important" class="button oauth github" on:click={handleGithubLogin} ><span class="fab fa-github"></span> Login with Github </a></li>
                            <!-- <li><a href="/#/" dis class="button oauth google"><span class="fab fa-google"></span> Login with Google</a></li> -->
                        </ul>
                    </div>

                    <div class="col-12">
                        <p>{errorMsg}</p>
                    </div>
                </div>
            </form>
        </div>
        <span class="image fidologo"><img src={svelteLogo} class="fidologo" alt="FIDO Logo" /></span>
    </div>
</section>



