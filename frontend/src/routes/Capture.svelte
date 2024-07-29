<script>
    import logo from "./../assets/images/logo.jpeg";
    import { Navbar, NavBrand, NavLi, NavUl, NavHamburger } from 'flowbite-svelte';
    import { Button } from "flowbite-svelte";
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
    // writeable interface array
  
    let isAdmin;
    let capture_started = false;
  
    let capture_filter = "";
    let capture_iface = "";
    let capture_promisc = false;
  
    const interfaces = writable([]);
    // Create a new store with the given data.
    let requests = [];
  
    // let resultText = "Please enter your name below 👇"
    // let name
  
    function parsePcapData(pcapData) {
      try {
        let packet = {};
        let parsed_packet = {};
        let packetData = pcapData.split("--- Layer 1 ---");
        packet["full_packet_data"] = packetData[0]
          .split("------------------------------------")[1]
          .trim();
        let temp = packetData[1].split("--- Layer 2 ---");
        packet["layer_1"] = temp[0].trim();
        temp = temp && temp.length > 1 ? temp[1].split("--- Layer 3 ---") : null;
        packet["layer_2"] = temp && temp.length > 0 ? temp[0].trim() : null;
        temp = temp && temp.length > 1 ? temp[1].split("--- Layer 4 ---") : null;
        packet["layer_3"] = temp && temp.length > 0 ? temp[0].trim() : null;
        temp = temp && temp.length > 1 ? temp[1].split("--- Layer 5 ---") : null;
        packet["layer_4"] = temp && temp.length > 0 ? temp[0].trim() : null;
        packet["layer_5"] = temp && temp.length > 1 ? temp[1].trim() : null;
  
        packet["layer_1"] = packet["layer_1"]
          ? packet["layer_1"].split(" ")
          : null;
        packet["layer_2"] = packet["layer_2"]
          ? packet["layer_2"].split(" ")
          : null;
        packet["layer_3"] = packet["layer_3"]
          ? packet["layer_3"].split(" ")
          : null;
        packet["layer_4"] = packet["layer_4"]
          ? packet["layer_4"].split(" ")
          : null;
        packet["layer_5"] = packet["layer_5"]
          ? packet["layer_5"].split(" ")
          : null;
  
        let packets_keys = Object.keys(packet);
        for (let i = 0; i < packets_keys.length; i++) {
          if (packets_keys[i] === "full_packet_data") {
            parsed_packet[packets_keys[i]] = packet[packets_keys[i]];
          } else {
            if (packet[packets_keys[i]] && packet[packets_keys[i]].length > 1) {
              let temp = packet[packets_keys[i]];
              let temp_obj = {};
              for (let j = 0; j < temp.length; j++) {
                if (j === 0) {
                  let key = "Protocol";
                  let value = temp[j].trim().split("\t")[0];
                  if (key && value) temp_obj[key] = value;
                } else {
                  let key = temp[j].split("=")[0];
                  let value = temp[j].split("=")[1];
                  if (key && value) temp_obj[key] = value;
                }
              }
              parsed_packet[packets_keys[i]] = temp_obj;
            }
          }
        }
  
        console.log("packet", parsed_packet);
        return packet;
      } catch (err) {
        console.log("Error in parsePcapData", err);
      }
    }
  
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
        const ws = new WebSocket("ws://localhost:4444/ws");
  
        ws.addEventListener("message", (message) => {
          let pcapData = parsePcapData(message.data);
          // console.log("Parsed", parsePcapData(message.data));
          // let pcapData = message.data;
          console.log("Received message from server: ", pcapData);
          // Parse the incoming message here
          // const data = JSON.parse(message.data);
          // Update the state.  That's literally it.  This can happen from anywhere:
          // we're not in a component, and there's no nested context.
          requests = [...requests, pcapData];
        });
      } catch (err) {
        console.log("Error in onMount", err);
      }
    });
  </script>
  
  <main>
    <Navbar  let:NavContainer color="none">
        <NavContainer class="border px-5 py-2 rounded-lg bg-white dark:bg-gray-600">
            <NavBrand href="/">
              <img src={logo} class="me-3 h-6 sm:h-9" alt="Flowbite Logo" />
              <!-- <span class="self-center whitespace-nowrap text-xl font-semibold">Flowbite</span> -->
            </NavBrand>
            </NavContainer>        
      </Navbar>
  
    {#if capture_started}
      <div class="packets_div">
        {#each requests as request}
          <div
            style="display: flex; flex-direction: row; align-items: center; justify-content: space-between;"
          >
            <p class="request">{request["full_packet_data"]}</p>
            <Button
              color="purple"
              style="width: 15%; height: 20px; border: 0px; align-self: auto;"
              >Details</Button
            >
          </div>
        {/each}
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
  