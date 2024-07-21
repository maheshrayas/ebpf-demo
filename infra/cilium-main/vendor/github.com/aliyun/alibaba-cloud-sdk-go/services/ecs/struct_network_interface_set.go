package ecs

//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
//
// Code generated by Alibaba Cloud SDK Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

// NetworkInterfaceSet is a nested struct in ecs response
type NetworkInterfaceSet struct {
	CreationTime                string                                      `json:"CreationTime" xml:"CreationTime"`
	VpcId                       string                                      `json:"VpcId" xml:"VpcId"`
	Type                        string                                      `json:"Type" xml:"Type"`
	Status                      string                                      `json:"Status" xml:"Status"`
	NetworkInterfaceTrafficMode string                                      `json:"NetworkInterfaceTrafficMode" xml:"NetworkInterfaceTrafficMode"`
	NetworkInterfaceName        string                                      `json:"NetworkInterfaceName" xml:"NetworkInterfaceName"`
	MacAddress                  string                                      `json:"MacAddress" xml:"MacAddress"`
	QueuePairNumber             int                                         `json:"QueuePairNumber" xml:"QueuePairNumber"`
	NetworkInterfaceId          string                                      `json:"NetworkInterfaceId" xml:"NetworkInterfaceId"`
	ServiceID                   int64                                       `json:"ServiceID" xml:"ServiceID"`
	InstanceId                  string                                      `json:"InstanceId" xml:"InstanceId"`
	OwnerId                     string                                      `json:"OwnerId" xml:"OwnerId"`
	ServiceManaged              bool                                        `json:"ServiceManaged" xml:"ServiceManaged"`
	VSwitchId                   string                                      `json:"VSwitchId" xml:"VSwitchId"`
	Description                 string                                      `json:"Description" xml:"Description"`
	ResourceGroupId             string                                      `json:"ResourceGroupId" xml:"ResourceGroupId"`
	ZoneId                      string                                      `json:"ZoneId" xml:"ZoneId"`
	PrivateIpAddress            string                                      `json:"PrivateIpAddress" xml:"PrivateIpAddress"`
	QueueNumber                 int                                         `json:"QueueNumber" xml:"QueueNumber"`
	DeleteOnRelease             bool                                        `json:"DeleteOnRelease" xml:"DeleteOnRelease"`
	SecurityGroupIds            SecurityGroupIdsInDescribeNetworkInterfaces `json:"SecurityGroupIds" xml:"SecurityGroupIds"`
	AssociatedPublicIp          AssociatedPublicIp                          `json:"AssociatedPublicIp" xml:"AssociatedPublicIp"`
	Attachment                  Attachment                                  `json:"Attachment" xml:"Attachment"`
	PrivateIpSets               PrivateIpSetsInDescribeNetworkInterfaces    `json:"PrivateIpSets" xml:"PrivateIpSets"`
	Ipv6Sets                    Ipv6SetsInDescribeNetworkInterfaces         `json:"Ipv6Sets" xml:"Ipv6Sets"`
	Ipv4PrefixSets              Ipv4PrefixSetsInDescribeNetworkInterfaces   `json:"Ipv4PrefixSets" xml:"Ipv4PrefixSets"`
	Ipv6PrefixSets              Ipv6PrefixSetsInDescribeNetworkInterfaces   `json:"Ipv6PrefixSets" xml:"Ipv6PrefixSets"`
	Tags                        TagsInDescribeNetworkInterfaces             `json:"Tags" xml:"Tags"`
}
