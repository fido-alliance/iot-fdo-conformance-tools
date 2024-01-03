<script lang="ts">
    import svelteLogo from '../assets/FIDO_Alliance_logo_black_RGB.webp'
    import {login, isLoggedIn, loginOnprem} from '../lib/User.api'
    import {push} from "svelte-spa-router"

    let email: string = ""
    let password: string = ""
    let errorMsg: string = ""

    const handleLogin = async (e) => {
        e.preventDefault()
        errorMsg = ""
        
        await loginOnprem()
        .then(() => {
            errorMsg = "Successfully logged in"
            window.setTimeout(() => push("/test"), 1000)
        })
        .catch((err) => {
            errorMsg = err
        })
    }

    isLoggedIn()
    .then(async (isActually) => {
        if (isActually) {
            push("/test")
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
                    <div class="col-9">
                        <ul class="actions">
                            <li><input type="submit" on:click={handleLogin} value="Login" class="primary" /></li>
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



