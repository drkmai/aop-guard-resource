package com.derekmai.aop.guard.resource;

/**
 * Interface to be implemented by entities that have an identifiable unique ID.
 *
 * <p>
 * Provides a method to retrieve the unique identifier of the implementing object.
 * </p>
 *
 * <p>
 * Typically used in access control or persistence layers where the entity's ID
 * is needed to verify ownership or association.
 * </p>
 */
public interface Identifiable {

  /**
   * Returns the unique identifier of the entity.
   *
   * @return the ID object (type can vary depending on implementation)
   */
  Object getId();
}
