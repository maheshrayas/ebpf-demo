// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeCiliumNodeConfigs implements CiliumNodeConfigInterface
type FakeCiliumNodeConfigs struct {
	Fake *FakeCiliumV2alpha1
	ns   string
}

var ciliumnodeconfigsResource = v2alpha1.SchemeGroupVersion.WithResource("ciliumnodeconfigs")

var ciliumnodeconfigsKind = v2alpha1.SchemeGroupVersion.WithKind("CiliumNodeConfig")

// Get takes name of the ciliumNodeConfig, and returns the corresponding ciliumNodeConfig object, and an error if there is any.
func (c *FakeCiliumNodeConfigs) Get(ctx context.Context, name string, options v1.GetOptions) (result *v2alpha1.CiliumNodeConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(ciliumnodeconfigsResource, c.ns, name), &v2alpha1.CiliumNodeConfig{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v2alpha1.CiliumNodeConfig), err
}

// List takes label and field selectors, and returns the list of CiliumNodeConfigs that match those selectors.
func (c *FakeCiliumNodeConfigs) List(ctx context.Context, opts v1.ListOptions) (result *v2alpha1.CiliumNodeConfigList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(ciliumnodeconfigsResource, ciliumnodeconfigsKind, c.ns, opts), &v2alpha1.CiliumNodeConfigList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v2alpha1.CiliumNodeConfigList{ListMeta: obj.(*v2alpha1.CiliumNodeConfigList).ListMeta}
	for _, item := range obj.(*v2alpha1.CiliumNodeConfigList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested ciliumNodeConfigs.
func (c *FakeCiliumNodeConfigs) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(ciliumnodeconfigsResource, c.ns, opts))

}

// Create takes the representation of a ciliumNodeConfig and creates it.  Returns the server's representation of the ciliumNodeConfig, and an error, if there is any.
func (c *FakeCiliumNodeConfigs) Create(ctx context.Context, ciliumNodeConfig *v2alpha1.CiliumNodeConfig, opts v1.CreateOptions) (result *v2alpha1.CiliumNodeConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(ciliumnodeconfigsResource, c.ns, ciliumNodeConfig), &v2alpha1.CiliumNodeConfig{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v2alpha1.CiliumNodeConfig), err
}

// Update takes the representation of a ciliumNodeConfig and updates it. Returns the server's representation of the ciliumNodeConfig, and an error, if there is any.
func (c *FakeCiliumNodeConfigs) Update(ctx context.Context, ciliumNodeConfig *v2alpha1.CiliumNodeConfig, opts v1.UpdateOptions) (result *v2alpha1.CiliumNodeConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(ciliumnodeconfigsResource, c.ns, ciliumNodeConfig), &v2alpha1.CiliumNodeConfig{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v2alpha1.CiliumNodeConfig), err
}

// Delete takes name of the ciliumNodeConfig and deletes it. Returns an error if one occurs.
func (c *FakeCiliumNodeConfigs) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(ciliumnodeconfigsResource, c.ns, name, opts), &v2alpha1.CiliumNodeConfig{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeCiliumNodeConfigs) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(ciliumnodeconfigsResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &v2alpha1.CiliumNodeConfigList{})
	return err
}

// Patch applies the patch and returns the patched ciliumNodeConfig.
func (c *FakeCiliumNodeConfigs) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v2alpha1.CiliumNodeConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(ciliumnodeconfigsResource, c.ns, name, pt, data, subresources...), &v2alpha1.CiliumNodeConfig{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v2alpha1.CiliumNodeConfig), err
}
