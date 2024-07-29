<script>
  import logo from "./../assets/images/logo.jpeg";
  import { Button } from "flowbite-svelte";
  import { userStore } from './../store/store';
  import { Label, Select } from "flowbite-svelte";
  import {
    Greet,
    IsRoot,
    StartCapture,
    GetAllDevices,
    StopCapture,
  } from "../../wailsjs/go/main/App.js";
  import { onMount } from "svelte";
  import { writable } from "svelte/store";
  import { get } from "svelte/store";
  import { navigate } from "svelte-routing";
  // writeable interface array

  let isAdmin;
  let capture_started = false;

  let capture_export = false;
  let capture_filter = "";
  let capture_iface = "";
  let capture_promisc = false;

  const interfaces = writable([]);
  // Create a new store with the given data.
  let requests = [];

  // let resultText = "Please enter your name below 👇"
  // let name



  onMount(async () => {
    try {
      isAdmin = await IsRoot();
      let ifaces_str = await GetAllDevices();
      if (ifaces_str == "") {
        console.log("No interfaces found");
      } else {
        console.log("ifaces_str", ifaces_str);
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

        console.log("interfaces", $interfaces.length);
      }
    } catch (err) {
      console.log("Error in onMount", err);
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
          <h1 style="font-size:medium; font-weight: bolder; width:300px">
            Select An Interface
          </h1>
          <div>
            <Select items={$interfaces} bind:value={capture_iface} />
          </div>
        </div>

        <div class="flex flex-row justify-items-start">
          <h1 style="font-size:medium; font-weight: bolder; width:300px">
            Promiscious Mode
          </h1>
          <div>
            <Select items={[
              { value: true, name: "Enable" },
              { value: false, name: "Disable" },
            ]} bind:value={capture_promisc} />
          </div>
        </div>

        <div class="flex flex-row justify-items-start">
          <h1 style="font-size:medium; font-weight: bolder; width:300px">
            Export Session to PCAP
          </h1>
          <div>
            <Select items={[
              { value: true, name: "Yes" },
              { value: false, name: "No" },
            ]} bind:value={capture_export} />
          </div>
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
    height: 300px;
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
