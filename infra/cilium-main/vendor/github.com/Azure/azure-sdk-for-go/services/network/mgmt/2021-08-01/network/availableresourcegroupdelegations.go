package network

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

import (
	"context"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/tracing"
	"net/http"
)

// AvailableResourceGroupDelegationsClient is the network Client
type AvailableResourceGroupDelegationsClient struct {
	BaseClient
}

// NewAvailableResourceGroupDelegationsClient creates an instance of the AvailableResourceGroupDelegationsClient
// client.
func NewAvailableResourceGroupDelegationsClient(subscriptionID string) AvailableResourceGroupDelegationsClient {
	return NewAvailableResourceGroupDelegationsClientWithBaseURI(DefaultBaseURI, subscriptionID)
}

// NewAvailableResourceGroupDelegationsClientWithBaseURI creates an instance of the
// AvailableResourceGroupDelegationsClient client using a custom endpoint.  Use this when interacting with an Azure
// cloud that uses a non-standard base URI (sovereign clouds, Azure stack).
func NewAvailableResourceGroupDelegationsClientWithBaseURI(baseURI string, subscriptionID string) AvailableResourceGroupDelegationsClient {
	return AvailableResourceGroupDelegationsClient{NewWithBaseURI(baseURI, subscriptionID)}
}

// List gets all of the available subnet delegations for this resource group in this region.
// Parameters:
// location - the location of the domain name.
// resourceGroupName - the name of the resource group.
func (client AvailableResourceGroupDelegationsClient) List(ctx context.Context, location string, resourceGroupName string) (result AvailableDelegationsResultPage, err error) {
	if tracing.IsEnabled() {
		ctx = tracing.StartSpan(ctx, fqdn+"/AvailableResourceGroupDelegationsClient.List")
		defer func() {
			sc := -1
			if result.adr.Response.Response != nil {
				sc = result.adr.Response.Response.StatusCode
			}
			tracing.EndSpan(ctx, sc, err)
		}()
	}
	result.fn = client.listNextResults
	req, err := client.ListPreparer(ctx, location, resourceGroupName)
	if err != nil {
		err = autorest.NewErrorWithError(err, "network.AvailableResourceGroupDelegationsClient", "List", nil, "Failure preparing request")
		return
	}

	resp, err := client.ListSender(req)
	if err != nil {
		result.adr.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "network.AvailableResourceGroupDelegationsClient", "List", resp, "Failure sending request")
		return
	}

	result.adr, err = client.ListResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "network.AvailableResourceGroupDelegationsClient", "List", resp, "Failure responding to request")
		return
	}
	if result.adr.hasNextLink() && result.adr.IsEmpty() {
		err = result.NextWithContext(ctx)
		return
	}

	return
}

// ListPreparer prepares the List request.
func (client AvailableResourceGroupDelegationsClient) ListPreparer(ctx context.Context, location string, resourceGroupName string) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"location":          autorest.Encode("path", location),
		"resourceGroupName": autorest.Encode("path", resourceGroupName),
		"subscriptionId":    autorest.Encode("path", client.SubscriptionID),
	}

	const APIVersion = "2021-08-01"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsGet(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/locations/{location}/availableDelegations", pathParameters),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// ListSender sends the List request. The method will close the
// http.Response Body if it receives an error.
func (client AvailableResourceGroupDelegationsClient) ListSender(req *http.Request) (*http.Response, error) {
	return client.Send(req, azure.DoRetryWithRegistration(client.Client))
}

// ListResponder handles the response to the List request. The method always
// closes the http.Response Body.
func (client AvailableResourceGroupDelegationsClient) ListResponder(resp *http.Response) (result AvailableDelegationsResult, err error) {
	err = autorest.Respond(
		resp,
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

// listNextResults retrieves the next set of results, if any.
func (client AvailableResourceGroupDelegationsClient) listNextResults(ctx context.Context, lastResults AvailableDelegationsResult) (result AvailableDelegationsResult, err error) {
	req, err := lastResults.availableDelegationsResultPreparer(ctx)
	if err != nil {
		return result, autorest.NewErrorWithError(err, "network.AvailableResourceGroupDelegationsClient", "listNextResults", nil, "Failure preparing next results request")
	}
	if req == nil {
		return
	}
	resp, err := client.ListSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		return result, autorest.NewErrorWithError(err, "network.AvailableResourceGroupDelegationsClient", "listNextResults", resp, "Failure sending next results request")
	}
	result, err = client.ListResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "network.AvailableResourceGroupDelegationsClient", "listNextResults", resp, "Failure responding to next results request")
	}
	return
}

// ListComplete enumerates all values, automatically crossing page boundaries as required.
func (client AvailableResourceGroupDelegationsClient) ListComplete(ctx context.Context, location string, resourceGroupName string) (result AvailableDelegationsResultIterator, err error) {
	if tracing.IsEnabled() {
		ctx = tracing.StartSpan(ctx, fqdn+"/AvailableResourceGroupDelegationsClient.List")
		defer func() {
			sc := -1
			if result.Response().Response.Response != nil {
				sc = result.page.Response().Response.Response.StatusCode
			}
			tracing.EndSpan(ctx, sc, err)
		}()
	}
	result.page, err = client.List(ctx, location, resourceGroupName)
	return
}
