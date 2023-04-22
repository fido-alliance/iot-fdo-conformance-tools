<script>
    import { getConfig, requestNewEmailValidationEmail } from "../lib/User.api";


    var errorMsg = ""
    var mode = ""

    const handleNewRequest = async (e) => {
        e.preventDefault()
        errorMsg = "" 
        
        if (mode != "online") {
            errorMsg = "This is only for Online mode"
            return
        }
        
        await requestNewEmailValidationEmail()
        .then((result) => {
            window.location.href = result;
        })
        .catch((err) => {
            errorMsg = err
        })
    }


    getConfig()
    .then((cfg) => {
        mode = cfg.mode;
    })

</script>
<section id="first" class="main special">
    <header class="major">
        <h2>Error: Your account pending approval.</h2>
    </header>
    <ul class="features">
        <li><p>Your account pending email validation. If you have not received email validation link, please press button down bellow to request it again.</p></li>
        <li><input type="submit" on:click={handleNewRequest} value="Request validation email again" class="primary" /></li>
    </ul>
</section>