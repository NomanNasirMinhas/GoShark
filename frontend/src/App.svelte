<script>
  import "./app.css";
  import { Router, Link, Route } from "svelte-routing";
  import Home from "./routes/Home.svelte";  
  import Capture from "./routes/Capture.svelte";
  import Splash from "./routes/Splash.svelte";

  export let url = "";
</script>

<Router {url}>  
  <div>
    <!-- <Route path="/blog/:id" component={BlogPost} />
    <Route path="/blog" component={Blog} />
    <Route path="/about" component={About} /> -->
    <Route path="/"><Splash /></Route>
    <Route path="/home"><Home /></Route>
    <Route path="/capture"><Capture /></Route>
  </div>
</Router>