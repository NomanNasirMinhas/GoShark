<script>
  // @ts-ignore
  import logo from "./../assets/images/logo.png";
  import { Button } from "flowbite-svelte";
  import { userStore } from './../store/store';
  // @ts-ignore
  import { Label, Select, Fileupload, Toast } from "flowbite-svelte";
  // @ts-ignore
  import { CheckCircleSolid, ExclamationCircleSolid, FireOutline, CloseCircleSolid } from 'flowbite-svelte-icons';
  import {
    // @ts-ignore
    Greet,
    IsRoot,
    // @ts-ignore
    StartCapture,
    GetAllDevices,
    // @ts-ignore
    StopCapture,
    ParseSuricataRules,
    // @ts-ignore
    LoadYaraRules
  } from "../../wailsjs/go/main/App.js";
  import { onMount } from "svelte";
  import { writable } from "svelte/store";
  // @ts-ignore
  import { get } from "svelte/store";
  import { navigate } from "svelte-routing";
  // writeable interface array

  let isAdmin;
  let capture_started = false;

  let capture_export = false;
  // @ts-ignore
  let capture_filter = "";
  let capture_iface = "";
  let capture_promisc = false;

  let suricataParsed = 0;
  let yaraParsed = 0;

  const interfaces = writable([]);
  // Create a new store with the given data.
  // @ts-ignore
  let requests = [];

  // let resultText = "Please enter your name below 👇"
  // let name

  let suricatafileprops = {
    id: 'user_avatar'
  };

  let yarafileprops = {
    id: 'user_avatar2'
  };

  let fileBytes = null;

  // @ts-ignore
  function readFileAsBytes(file) {
    const reader = new FileReader();
    reader.onload = (event) => {
      // @ts-ignore
      fileBytes = new Uint8Array(event.target.result);
      //console.log('File bytes:', fileBytes);
    };
    
    reader.onerror = (event) => {
      console.error('Error reading file:', event);
    };
    reader.readAsArrayBuffer(file);
  }

  function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

  const handleSuricataSelection = async (event) => {
    
    const files = event.target.files;
    if (files.length > 0) {
      try{
      const file = files[0];
      // @ts-ignore
      readFileAsBytes(file)
      await sleep(100)
      
      if(!fileBytes){
        suricataParsed = -1
        return
      }
      fileBytes = Array.from(fileBytes)
      //console.log('File bytes 2 :', fileBytes);
      
      let parsed = await ParseSuricataRules(file.name, fileBytes)
      fileBytes = []
      //console.log("Suricata Parsed", parsed)
      if(!parsed){
        suricataParsed = -1;
      } else{
        suricataParsed = 1;
      }
    } catch (e){      
      //console.log("Ex:", e)      
    }
    }
  };

  const handleYaraSelection = async (event) => {
    
    const files = event.target.files;
    if (files.length > 0) {
      try{
      const file = files[0];
      // @ts-ignore
      readFileAsBytes(file)
      await sleep(100)
      
      if(!fileBytes){
        yaraParsed = -1
        return
      }
      fileBytes = Array.from(fileBytes)
      //console.log('File bytes 2 :', fileBytes);
      
      let parsed = await LoadYaraRules(file.name, fileBytes)
      fileBytes = []
      //console.log("Suricata Parsed", parsed)
      if(!parsed){
        yaraParsed = -1;
      } else{
        yaraParsed = 1;
      }
    } catch (e){      
      //console.log("Ex:", e)      
    }
    }
  };


  onMount(async () => {
    try {
      isAdmin = await IsRoot();
      let ifaces_str = await GetAllDevices();
      if (ifaces_str == "") {
        //console.log("No interfaces found");
      } else {
        //console.log("ifaces_str", ifaces_str);
        let temp_interfaces = ifaces_str.split(",");
        for (let i = 0; i < temp_interfaces.length; i++) {
          if (temp_interfaces[i] != "") {
            let obj = {
              value: temp_interfaces[i].split(":")[0],
              name: temp_interfaces[i],
            };
            interfaces.update((old) => [...old, obj]);
            // interfaces.push({
            //   value: temp_interfaces[i].split(":")[0],
            //   name: temp_interfaces[i],
            // })
          }
        }

        //console.log("interfaces", $interfaces.length);
      }
    } catch (err) {
      //console.log("Error in onMount", err);
    }
  });
</script>

<main>    
    
    <img alt="Wails logo" id="logo" src={logo} />
    <!-- <p style="margin-top: -50px;" class="text-lg dark:text-white">GoShark</p> -->
    <!-- <div class="result" id="result">{resultText}</div> -->
    {#if !isAdmin}
    <div class="result" id="result">
      You are not an admin. Program will not work properly.
    </div>
    {/if}
    {#if $interfaces.length > 0}
    <div>
      <div class="input-box" id="input">
        <div class="flex flex-row justify-items-start">
          <h4 style="font-size:medium; width:300px">
            Select An Interface
          </h4>
          <div>
            <Select items={$interfaces} bind:value={capture_iface} />
          </div>
        </div>
        
        <div class="flex flex-row justify-items-start">
          <h4 style="font-size:medium; width:300px">
            Promiscious Mode
          </h4>
          <div>
            <Select items={[
              { value: true, name: "Enable" },
              { value: false, name: "Disable" },
            ]} bind:value={capture_promisc} />
          </div>
        </div>
        
        <div class="flex flex-row justify-items-start">
          <h4 style="font-size:medium; width:300px">
            Export Session to PCAP
          </h4>
          <div>
            <Select items={[
              { value: true, name: "Yes" },
              { value: false, name: "No" },
            ]} bind:value={capture_export} />
          </div>
        </div>
        
        <div class="flex flex-row justify-items-start">
          <h4 style="font-size:medium; width:300px">
            Suricata Rules File
          </h4>
          <Fileupload class="w-96" {...suricatafileprops} on:change={handleSuricataSelection} />
        </div>
        
        <div class="flex flex-row justify-items-start">
          <h4 style="font-size:medium; width:300px">
            YARA Rules Files
          </h4>
          <Fileupload class="w-96" {...yarafileprops} on:change={handleYaraSelection} />
        </div>
        
      </div>
      <Button
      color={capture_started ? "red" : "green"}
      disabled={!isAdmin || capture_iface == "" || capture_promisc == null}
      on:click={()=>{
        userStore.update((old) => ({...old, capture_iface: capture_iface, capture_promisc: capture_promisc, filter: '', capture_export: capture_export}));
        navigate("/capture")
      }}
      >
      {!capture_started ? "Capture" : "Stop"}
    </Button>
  </div>
  {/if}

<p class="h-16"></p>

{#if suricataParsed === -1}
  <Toast color="red" class = "z-10 m-auto">
    <svelte:fragment slot="icon">
      <ExclamationCircleSolid class="w-5 h-5" />
      <span class="sr-only">Warning icon</span>
    </svelte:fragment>
    Unable to parse Suricata/Snort Rules file.
  </Toast>
  {/if}

  {#if yaraParsed === -1}
  <Toast color="red" class = "z-10 m-auto">
    <svelte:fragment slot="icon">
      <ExclamationCircleSolid class="w-5 h-5" />
      <span class="sr-only">Warning icon</span>
    </svelte:fragment>
    Unable to parse Yara Rules file.
  </Toast>
  {/if}

  {#if suricataParsed === 1}
  <Toast color="green" class = "z-10 m-auto">
    <svelte:fragment slot="icon">
      <ExclamationCircleSolid class="w-5 h-5" />
      <span class="sr-only">Success icon</span>
    </svelte:fragment>
    Suricata/Snort Rules is Valid.
  </Toast>
  {/if}

  {#if yaraParsed === 1}
  <Toast color="green" class = "z-10 m-auto">
    <svelte:fragment slot="icon">
      <ExclamationCircleSolid class="w-5 h-5" />
      <span class="sr-only">Success icon</span>
    </svelte:fragment>
    Yara Rules file is Valid.
  </Toast>
  {/if}

</main>

<style>
  #logo {
    display: block;
    /* width: 30%; */
    height: 300px;
    margin: auto;
    padding: 2% 0 0;
    background-position: center;
    background-repeat: no-repeat;
    background-size: 100% 100%;
    background-origin: content-box;
  }

  .request {
    height: 20px;
    margin: 0;
    padding-left: 10px;
    padding-right: 10px;
    font-size: 12px;
    font-style: italic;
    color: #fff;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    width: 80%;
    border: #e2ebf0 1px solid;
    background-color: rgb(41, 1, 45);
    margin-bottom: 10px;
  }

  .packets_div {
    margin: 1.5rem auto;
    width: 70%;
    height: 500px;
    overflow-y: scroll;
    overflow-wrap: break-word;
    border: 1px solid #03104e;
    border-radius: 5px;
    padding: 10px;
    background-color: rgb(1, 29, 19);
  }

  .result {
    height: 20px;
    line-height: 20px;
    margin: 1.5rem auto;
  }

  .input-box {
    display: flex;
    flex-direction: column;
    justify-content: space-evenly;
    align-items: flex-start;
    margin: 1.5rem auto;
    width: 80%;
    height: 50vh;
    border: 5px solid #f4f5f6;
    padding: 20px;
  }

  .input-box .btn {
    width: 60px;
    height: 30px;
    line-height: 30px;
    border-radius: 3px;
    border: none;
    margin: 0 0 0 20px;
    padding: 0 8px;
    cursor: pointer;
  }

  .input-box .btn:hover {
    background-image: linear-gradient(to top, #cfd9df 0%, #e2ebf0 100%);
    color: #333333;
  }

  .input-box .input {
    border: none;
    border-radius: 3px;
    outline: none;
    height: 30px;
    line-height: 30px;
    padding: 0 10px;
    background-color: rgba(240, 240, 240, 1);
    -webkit-font-smoothing: antialiased;
  }

  .input-box .input:hover {
    border: none;
    background-color: rgba(255, 255, 255, 1);
  }

  .input-box .input:focus {
    border: none;
    background-color: rgba(255, 255, 255, 1);
  }
</style>
